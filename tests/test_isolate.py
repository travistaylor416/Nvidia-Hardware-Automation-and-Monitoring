"""Fault isolation scenarios: each test builds two link ends and checks the verdict."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nvmon.inventory import Link  # noqa: E402
from nvmon.metrics.isolate import analyze  # noqa: E402
from nvmon.models import FAIL, INFO, PASS, WARN, PortSample  # noqa: E402
from nvmon.settings import Thresholds  # noqa: E402

TH = Thresholds()
LINK = Link("leaf1", "sw1p1", "dgx1", "mlx5_0/1")


def end(device, port, role, **kw):
    base = dict(oper="up", admin="up", media="optical",
                dom={"rx_power_dbm": [-2.0] * 4, "tx_power_dbm": [-1.0] * 4, "temperature_c": [45.0]},
                counters={"crc_errors": 0, "symbol_errors": 0, "link_downed": 0})
    base.update(kw)
    return PortSample(device, role, "nvos" if role == "switch" else "ubuntu", port, **base)


def healthy():
    return end("leaf1", "sw1p1", "switch"), end("dgx1", "mlx5_0/1", "server")


def run(a, b, prev=None, links=(LINK,)):
    return analyze([a, b], list(links), TH, previous=prev)[0]


class IsolationTests(unittest.TestCase):
    def test_healthy(self):
        r = run(*healthy())
        self.assertEqual((r.status, r.component), (PASS, "none"))

    def test_fiber_loss(self):
        a, b = healthy()
        b.dom["rx_power_dbm"] = [-14.0, -2.0, -2.0, -2.0]
        r = run(a, b)
        self.assertEqual(r.component, "cable")
        self.assertEqual(r.status, WARN)
        self.assertIn("lost in the fiber", r.evidence[0])

    def test_failing_switch_laser(self):
        a, b = healthy()
        a.dom["tx_power_dbm"] = [-12.0, -1.0, -1.0, -1.0]
        b.dom["rx_power_dbm"] = [-15.0, -2.0, -2.0, -2.0]
        r = run(a, b)
        self.assertEqual(r.component, "switch_transceiver")
        self.assertEqual(r.location, "transceiver at leaf1:sw1p1")

    def test_module_thresholds_win_over_defaults(self):
        a, b = healthy()
        b.dom["rx_power_dbm"] = [-11.0] * 4                  # below default -10
        b.thresholds = {"rx_power_dbm_low_warn": -12.0, "rx_power_dbm_low_alarm": -14.0}
        self.assertEqual(run(a, b).status, PASS)

    def test_dark_rx_is_fail(self):
        a, b = healthy()
        b.dom["rx_power_dbm"] = [-40.0] * 4
        self.assertEqual(run(a, b).status, FAIL)

    def test_errors_both_directions_point_at_cable(self):
        a, b = healthy()
        prev = {(x.device, x.port): copy.deepcopy(x) for x in (a, b)}
        a.counters["crc_errors"] = 500
        b.counters["symbol_errors"] = 50
        r = run(a, b, prev)
        self.assertEqual(r.component, "cable")
        self.assertEqual(r.status, FAIL)

    def test_one_direction_optical_is_ambiguous(self):
        a, b = healthy()
        prev = {(x.device, x.port): copy.deepcopy(x) for x in (a, b)}
        b.counters["symbol_errors"] = 20
        r = run(a, b, prev)
        self.assertEqual(r.component, "ambiguous")
        self.assertTrue(any("leaf1:sw1p1 -> dgx1:mlx5_0/1" in e for e in r.evidence))

    def test_one_direction_copper_points_at_cable(self):
        a, b = healthy()
        for x in (a, b):
            x.media, x.dom = "copper", {}
        prev = {(x.device, x.port): copy.deepcopy(x) for x in (a, b)}
        b.counters["crc_errors"] = 20
        self.assertEqual(run(a, b, prev).component, "cable")

    def test_cumulative_counters_only_warn(self):
        a, b = healthy()
        b.counters["crc_errors"] = 5000
        r = run(a, b)
        self.assertEqual(r.status, WARN)
        self.assertTrue(any("lifetime" in e for e in r.evidence))

    def test_counter_reset_not_negative(self):
        a, b = healthy()
        prev = {(x.device, x.port): copy.deepcopy(x) for x in (a, b)}
        prev[("leaf1", "sw1p1")].counters["crc_errors"] = 1000   # cleared since last sample
        self.assertEqual(run(a, b, prev).status, PASS)

    def test_missing_module(self):
        a, b = healthy()
        b.media, b.oper, a.oper = "absent", "down", "down"
        r = run(a, b)
        self.assertEqual((r.status, r.component), (FAIL, "node_transceiver"))

    def test_ib_init_is_subnet_manager(self):
        a, b = healthy()
        a.oper = b.oper = "init"
        self.assertEqual(run(a, b).component, "subnet_manager")

    def test_admin_down_skipped(self):
        a, b = healthy()
        a.admin, a.oper, b.oper = "down", "down", "down"
        self.assertEqual(run(a, b).status, INFO)

    def test_alias_lookup(self):
        a, b = healthy()
        b.port, b.aliases = "ibp12s0", ["mlx5_0/1"]
        self.assertEqual(run(a, b).status, PASS)

    def test_switch_to_switch_locations_distinct(self):
        a = end("leaf1", "sw32p1", "switch")
        b = end("spine1", "sw1p1", "switch", dom={"rx_power_dbm": [-2.0] * 4, "tx_power_dbm": [-12.0] * 4})
        r = run(a, b, links=[Link("leaf1", "sw32p1", "spine1", "sw1p1")])
        self.assertEqual(r.location, "transceiver at spine1:sw1p1")

    def test_unmapped_endpoint(self):
        smp = end("leaf1", "sw9p1", "switch", dom={"rx_power_dbm": [-15.0], "tx_power_dbm": [-1.0]})
        r = analyze([smp], [], TH)[0]
        self.assertEqual((r.component, r.mapped), ("cable_or_far_end", False))

    def test_missing_end_reports_info(self):
        a, _ = healthy()
        r = analyze([a], [LINK], TH)[0]
        self.assertEqual(r.status, INFO)
        self.assertIn("no metrics for end B", r.summary)


if __name__ == "__main__":
    unittest.main()
