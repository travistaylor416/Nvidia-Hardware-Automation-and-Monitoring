"""Prometheus exposition, Jira ticketing (with a fake client) and settings loading."""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nvmon import settings as settings_mod  # noqa: E402
from nvmon.models import FAIL, WARN, DeviceReport, Finding, LinkResult, PortSample  # noqa: E402
from nvmon.outputs import jira, prometheus  # noqa: E402
from nvmon.settings import Settings, load  # noqa: E402


class PrometheusTests(unittest.TestCase):
    def setUp(self):
        settings_mod.set_current(Settings())

    def test_build(self):
        smp = PortSample("leaf1", "switch", "nvos", "sw1p1", oper="up", admin="up", media="optical",
                         counters={"crc_errors": 3}, dom={"rx_power_dbm": [-2.5, -3.0], "temperature_c": [40.0]},
                         module={"vendor": 'Ven"dor'})
        lr = LinkResult("leaf1:sw1p1<->dgx1:mlx5_0/1", "leaf1", "sw1p1", "dgx1", "mlx5_0/1", status=FAIL,
                        component="cable", location="cable/fiber between x and y", summary="s")
        rep = DeviceReport("dgx1", "ubuntu", "server", "10.0.0.1")
        rep.add("DNS resolvers", WARN, "x")
        text = prometheus.build([smp], [lr], {"leaf1": {"role": "switch", "os": "nvos", "up": True}}, [rep])

        self.assertIn('nvmon_port_crc_errors_total{device="leaf1",port="sw1p1",role="switch"} 3', text)
        self.assertIn('nvmon_port_rx_power_dbm{device="leaf1",port="sw1p1",role="switch",lane="2"} -3', text)
        self.assertIn('vendor="Ven\\"dor"', text)
        self.assertIn('component="cable"} 1', text)
        self.assertIn('nvmon_check_status{device="dgx1",role="server",os="ubuntu",check="DNS resolvers"} 1', text)
        # each family declared exactly once
        types = re.findall(r"^# TYPE (\S+)", text, re.M)
        self.assertEqual(len(types), len(set(types)))
        # every sample line is name{labels} value
        for line in text.splitlines():
            if not line.startswith("#"):
                self.assertRegex(line, r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{.*\})? \S+$")

    def test_textfile_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = prometheus.write_textfile("a 1\n", Path(tmp) / "sub" / "nvmon.prom")
            self.assertEqual(Path(path).read_text(), "a 1\n")
            self.assertEqual([p.name for p in Path(path).parent.iterdir()], ["nvmon.prom"])


class FakeJira:
    def __init__(self, existing=None):
        self.existing = existing or {}
        self.created, self.comments = [], []

    def find_open(self, label):
        return self.existing.get(label)

    def create(self, fields):
        self.created.append(fields)
        key = f"NET-{len(self.created)}"
        self.existing[fields["labels"][-1]] = key
        return key

    def comment(self, key, text):
        self.comments.append(key)


class JiraTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Settings()
        self.s.general.state_dir = self.tmp.name
        j = self.s.jira
        j.enabled, j.dry_run, j.url, j.project_key = True, False, "https://jira.example.com", "NET"
        self.findings = [Finding("check|dgx1|DNS resolvers", "dgx1", FAIL, "dgx1: DNS resolvers", "missing 10.10.10.20"),
                         Finding("check|dgx1|BMC config", "dgx1", FAIL, "dgx1: BMC config", "ip mismatch"),
                         Finding("check|dgx2|DNS PTR", "dgx2", WARN, "dgx2: DNS PTR", "no PTR")]

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_then_dedupe_then_comment_on_change(self):
        fake = FakeJira()
        out = jira.raise_tickets(self.findings, self.s, client=fake)
        self.assertEqual(len(fake.created), 1, out)               # WARN below min_severity, grouped by device
        f = fake.created[0]
        self.assertEqual(f["project"], {"key": "NET"})
        self.assertEqual(f["priority"], {"name": "High"})
        self.assertTrue(f["labels"][-1].startswith("nvmon-"))
        self.assertIn("{noformat}", f["description"])

        jira.raise_tickets(self.findings, self.s, client=fake)    # unchanged -> no new issue, no comment
        self.assertEqual((len(fake.created), len(fake.comments)), (1, 0))

        jira.raise_tickets(self.findings[:1], self.s, client=fake)  # finding set changed -> comment
        self.assertEqual((len(fake.created), fake.comments), (1, ["NET-1"]))

    def test_group_by_finding_and_cap(self):
        self.s.jira.group_by, self.s.jira.max_issues_per_run = "finding", 1
        fake = FakeJira()
        out = jira.raise_tickets(self.findings, self.s, client=fake)
        self.assertEqual(len(fake.created), 1)
        self.assertTrue(any("max_issues_per_run" in line for line in out))

    def test_dry_run_sends_nothing(self):
        self.s.jira.dry_run = True
        out = jira.raise_tickets(self.findings, self.s, client=None)
        self.assertTrue(out[0].startswith("jira DRY RUN"))
        self.assertFalse(any(Path(self.tmp.name).iterdir()))

    def test_disabled(self):
        self.s.jira.enabled = False
        self.assertIn("disabled", jira.raise_tickets(self.findings, self.s, client=FakeJira())[0])

    def test_adf_for_api_v3(self):
        self.s.jira.api_version = "3"
        body = jira.build_fields(self.s.jira, "s", "d", FAIL, "nvmon-x")["description"]
        self.assertEqual(body["type"], "doc")

    def test_client_requires_credentials(self):
        with self.assertRaises(jira.JiraError):
            jira.JiraClient(self.s.jira, user=None, token=None)

    def test_link_findings(self):
        lr = LinkResult("a:1<->b:2", "a", "1", "b", "2", status=FAIL, component="cable",
                        location="cable/fiber between a:1 and b:2", evidence=["Rx low"], action="clean")
        f = jira.findings_from([], [lr])[0]
        self.assertEqual((f.key, f.device), ("link|a:1<->b:2", "a"))
        self.assertIn("Suspected: cable/fiber", f.detail)


class SettingsTests(unittest.TestCase):
    def test_env_overrides(self):
        env = {"NVMON_JIRA_PROJECT_KEY": "NET", "NVMON_JIRA_ENABLED": "yes", "NVMON_CHECKS_BMC_TCP_PORTS": "443,623",
               "NVMON_JIRA_PRIORITY_MAP": '{"FAIL": "Highest"}', "NVMON_THRESHOLDS_RX_POWER_LOW_DBM": "-9.5",
               "NVMON_PROMETHEUS_OUTPUTS": "http,textfile"}
        s = load(path=None, environ=env)
        self.assertEqual(s.jira.project_key, "NET")
        self.assertIs(s.jira.enabled, True)
        self.assertEqual(s.checks.bmc_tcp_ports, [443, 623])
        self.assertEqual(s.jira.priority_map, {"FAIL": "Highest"})
        self.assertEqual(s.thresholds.rx_power_low_dbm, -9.5)
        self.assertEqual(s.prometheus.outputs, ["http", "textfile"])

    def test_toml_then_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.toml"
            p.write_text('[jira]\nproject_key = "OPS"\nlabels = ["a", "b"]\n[general]\nworkers = 3\n')
            s = load(str(p), environ={"NVMON_GENERAL_WORKERS": "5"})
            self.assertEqual((s.jira.project_key, s.jira.labels, s.general.workers), ("OPS", ["a", "b"], 5))

    def test_secret_in_toml_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.toml"
            p.write_text('[jira]\napi_token = "abc"\n')
            with self.assertRaises(ValueError):
                load(str(p), environ={})

    def test_example_config_loads(self):
        s = load(str(Path(__file__).resolve().parent.parent / "nvmon.example.toml"), environ={})
        self.assertEqual(s.ssh.host_key_policy, "reject")
        self.assertIs(s.jira.dry_run, True)

    def test_config_dump_has_no_secret_values(self):
        os.environ["NVMON_JIRA_TOKEN"] = "super-secret-value"
        try:
            dumped = json.dumps(Settings().to_dict())
            self.assertNotIn("super-secret-value", dumped)
            self.assertIn('"jira_token": true', dumped)
        finally:
            del os.environ["NVMON_JIRA_TOKEN"]


if __name__ == "__main__":
    unittest.main()
