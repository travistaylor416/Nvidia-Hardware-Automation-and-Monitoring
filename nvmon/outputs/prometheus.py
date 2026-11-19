"""
Prometheus exposition (text format 0.0.4) without third-party libraries.

Delivery options (settings.prometheus.outputs):
    http         built-in /metrics endpoint (see outputs/exporter.py) - Prometheus scrapes it
    textfile     atomically written .prom file for node_exporter's textfile collector
    pushgateway  HTTP PUT to a Pushgateway (for cron / one-shot runs)

Metric names use settings.prometheus.metric_prefix (default "nvmon").  The Grafana dashboard in
deploy/grafana assumes the default prefix.
"""

import base64
import math
import os
import ssl
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import quote

from .. import settings as settings_mod
from ..metrics.parse import DOM_UNITS
from ..models import STATUS_VALUE

COMPONENTS = ["none", "switch_port", "switch_transceiver", "node_port", "node_transceiver", "cable",
              "cable_or_far_end", "subnet_manager", "ambiguous", "unknown"]

COUNTER_HELP = {
    "crc_errors": "Frames received with CRC/FCS errors",
    "symbol_errors": "Physical-layer symbol errors received",
    "fec_corrected": "FEC corrected blocks/bits",
    "fec_uncorrectable": "FEC uncorrectable blocks",
    "link_downed": "Times the link went down (or carrier changes)",
    "link_error_recovery": "InfiniBand link error recovery events",
    "local_link_integrity_errors": "InfiniBand local link integrity errors",
    "excessive_buffer_overrun": "InfiniBand excessive buffer overrun errors",
    "rx_remote_phy_errors": "Packets received with remote physical errors",
    "rx_errors": "Receive errors",
    "tx_discards": "Transmit discards",
}
DOM_METRIC = {
    "rx_power_dbm": ("port_rx_power_dbm", "Received optical power per lane (dBm)"),
    "tx_power_dbm": ("port_tx_power_dbm", "Transmitted optical power per lane (dBm)"),
    "tx_bias_ma": ("port_tx_bias_milliamps", "Laser bias current per lane (mA)"),
    "temperature_c": ("port_module_temperature_celsius", "Transceiver temperature (C)"),
    "voltage_v": ("port_module_voltage_volts", "Transceiver supply voltage (V)"),
}


def _escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _num(value):
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "NaN"
    if isinstance(value, float) and math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if float(value).is_integer() and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


class Registry:
    def __init__(self, prefix="nvmon"):
        self.prefix = prefix
        self.families = {}

    def add(self, name, mtype, help_text, labels, value):
        full = f"{self.prefix}_{name}"
        fam = self.families.setdefault(full, {"type": mtype, "help": help_text, "samples": []})
        fam["samples"].append((labels, value))

    def render(self):
        lines = []
        for name, fam in self.families.items():
            lines.append(f"# HELP {name} {fam['help']}")
            lines.append(f"# TYPE {name} {fam['type']}")
            for labels, value in fam["samples"]:
                lbl = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
                lines.append(f"{name}{{{lbl}}} {_num(value)}" if lbl else f"{name} {_num(value)}")
        return "\n".join(lines) + "\n"


def build(samples=None, link_results=None, device_status=None, reports=None, prefix=None):
    """
    samples:        [PortSample]
    link_results:   [LinkResult]
    device_status:  {device_name: {"role", "os", "up": bool, "duration": float, "timestamp": float}}
    reports:        [DeviceReport] from health checks (optional)
    """
    reg = Registry(prefix or settings_mod.current().prometheus.metric_prefix)

    for name, st in (device_status or {}).items():
        base = {"device": name, "role": st.get("role", ""), "os": st.get("os", "")}
        reg.add("up", "gauge", "1 if nvmon could collect from the device over SSH", base, 1 if st.get("up") else 0)
        reg.add("collect_duration_seconds", "gauge", "Time spent collecting from the device", base, st.get("duration", 0))
        reg.add("last_collect_timestamp_seconds", "gauge", "Unix time of the last collection", base, st.get("timestamp", 0))

    for smp in samples or []:
        base = {"device": smp.device, "port": smp.port, "role": smp.role}
        reg.add("port_oper_up", "gauge", "1 if the port is operationally up (0.5 = IB Init/Armed)", base,
                1 if smp.oper == "up" else 0.5 if smp.oper == "init" else 0)
        reg.add("port_admin_up", "gauge", "1 if the port is administratively enabled", base, 0 if smp.admin == "down" else 1)
        reg.add("port_module_info", "gauge", "Transceiver/cable identity (value always 1)",
                {**base, "media": smp.media, "vendor": smp.module.get("vendor", ""),
                 "part": smp.module.get("part", ""), "identifier": smp.module.get("identifier", "")}, 1)
        for key, value in sorted(smp.counters.items()):
            reg.add(f"port_{key}_total", "counter", COUNTER_HELP.get(key, key), base, value)
        for key, value in sorted(smp.ber.items()):
            reg.add(f"port_{key}", "gauge", f"Bit error ratio ({key})", base, value)
        for key, values in smp.dom.items():
            metric, help_text = DOM_METRIC.get(key, (f"port_{key}", key))
            if key in ("temperature_c", "voltage_v"):
                reg.add(metric, "gauge", help_text, base, max(values))
            else:
                for lane, value in enumerate(values, start=1):
                    reg.add(metric, "gauge", help_text, {**base, "lane": str(lane)}, value)
        for key, value in sorted(smp.thresholds.items()):
            reg.add("port_module_threshold", "gauge", f"Thresholds reported by the module ({', '.join(DOM_UNITS.values())})",
                    {**base, "threshold": key}, value)
        for alarm in smp.alarms:
            reg.add("port_module_alarm", "gauge", "Module alarm/warning flag currently asserted", {**base, "alarm": alarm}, 1)

    for lr in link_results or []:
        base = {"link": lr.link_id, "a_device": lr.a_device, "a_port": lr.a_port, "b_device": lr.b_device,
                "b_port": lr.b_port, "media": lr.media, "mapped": "true" if lr.mapped else "false"}
        reg.add("link_status", "gauge", "Link health: 0 ok, 1 warning, 2 fault", base, STATUS_VALUE.get(lr.status, 0))
        for comp in COMPONENTS:
            reg.add("link_fault_component", "gauge",
                    "1 for the component nvmon believes is at fault on this link (one-hot)",
                    {**base, "component": comp}, 1 if lr.component == comp else 0)
        if lr.status in ("WARN", "FAIL"):
            reg.add("link_fault_info", "gauge", "Human-readable fault location (value = status)",
                    {**base, "component": lr.component, "location": lr.location, "summary": lr.summary[:200]},
                    STATUS_VALUE.get(lr.status, 0))

    for rep in reports or []:
        base = {"device": rep.name, "role": rep.role, "os": rep.os}
        reg.add("device_status", "gauge", "Health check result: 0 pass, 1 warn, 2 fail", base, STATUS_VALUE[rep.status])
        for chk in rep.checks:
            reg.add("check_status", "gauge", "Individual health check: 0 pass/info, 1 warn, 2 fail",
                    {**base, "check": chk.name}, STATUS_VALUE[chk.status])
    return reg.render()


# --------------------------------------------------------------------------- delivery


def write_textfile(text, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".nvmon-", suffix=".prom.tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)  # atomic so node_exporter never reads a half-written file
    return str(path)


def ssl_context(verify=True, ca_bundle=""):
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=ca_bundle or None)


def push(text, s=None, instance="nvmon"):
    p = (s or settings_mod.current()).prometheus
    if not p.pushgateway_url:
        raise ValueError("prometheus.pushgateway_url is not set")
    url = f"{p.pushgateway_url.rstrip('/')}/metrics/job/{quote(p.pushgateway_job, safe='')}/instance/{quote(instance, safe='')}"
    req = urllib.request.Request(url, data=text.encode(), method="PUT",
                                 headers={"Content-Type": "text/plain; version=0.0.4"})
    user, pw = settings_mod.secret("pushgateway_user"), settings_mod.secret("pushgateway_password")
    if user:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw or ''}".encode()).decode())
    ctx = ssl_context(p.verify_tls, p.ca_bundle) if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return resp.status


def deliver(text, s=None, outputs=None):
    """Write/push according to settings (the http output is served by the exporter loop)."""
    s = s or settings_mod.current()
    done = []
    for out in outputs if outputs is not None else s.prometheus.outputs:
        if out == "textfile":
            if not s.prometheus.textfile_path:
                done.append("textfile skipped: prometheus.textfile_path not set")
            else:
                done.append(f"textfile written: {write_textfile(text, s.prometheus.textfile_path)}")
        elif out == "pushgateway":
            try:
                done.append(f"pushgateway: HTTP {push(text, s)}")
            except Exception as exc:  # noqa: BLE001
                done.append(f"pushgateway FAILED: {exc}")
    return done
