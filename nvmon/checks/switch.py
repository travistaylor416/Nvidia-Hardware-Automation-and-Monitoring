"""
Switch checks for NVOS (InfiniBand, e.g. QM9700) and Cumulus Linux (Spectrum Ethernet):

    Reachability  ping mgmt IP
    OS            `nv show system` version (+ optional expected version)
    Ports         `nv show interface` -> each data port up / down / init / admin-down
    Port diag     for each problem port run settings.switch.<os>_diag_commands and derive hints

`nv show interface -o json` field names differ between releases, so the parser checks several
candidate keys and falls back to the text table.
"""

import fnmatch
import json
import re

from .. import netutil
from ..models import FAIL, INFO, PASS, WARN, DeviceReport, PortDiag, guarded
from ..ssh import open_session, safe_token

UP_WORDS = {"up", "active", "linkup", "link up", "enabled"}
DOWN_WORDS = {"down", "polling", "disabled", "sleep", "linkdown", "link down", "offline",
              "not present", "lowerlayerdown", "notpresent"}
INIT_WORDS = {"init", "initialize", "armed"}  # IB: physical link up, Subnet Manager has not activated it

OPER_KEYS = ("oper-status", "oper-state", "logical-state", "physical-state", "state", "link-state")
ADMIN_KEYS = ("admin-status", "admin-state")

# ------------------------------------------------------------------ parsing (pure, unit tested)


def _word(value):
    """nv JSON sometimes encodes state as {"up": {}} instead of "up"."""
    if isinstance(value, dict):
        value = next(iter(value), "")
    return str(value or "").strip().lower()


def classify(states):
    words = [w for w in (_word(s) for s in states) if w]
    if any(w in INIT_WORDS for w in words):
        return "init"
    if any(w in DOWN_WORDS for w in words):
        return "down"
    if any(w in UP_WORDS for w in words):
        return "up"
    return "unknown"


def extract_json(text):
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    if not starts:
        raise ValueError("no JSON in output")
    return json.loads(text[min(starts):])


def parse_interface_json(data):
    if isinstance(data, list):
        data = {item.get("name") or item.get("interface"): item for item in data if isinstance(item, dict)}
    ports = []
    for name, body in (data or {}).items():
        if not isinstance(body, dict):
            continue
        link = body.get("link") if isinstance(body.get("link"), dict) else {}
        merged = {**body, **link}
        oper_vals = {k: merged[k] for k in OPER_KEYS if k in merged}
        admin_val = next((merged[k] for k in ADMIN_KEYS if k in merged), None)
        # Cumulus: link.state is the *admin* setting when an oper-status field also exists.
        if admin_val is None and "oper-status" in merged and "state" in merged:
            admin_val = merged["state"]
            oper_vals.pop("state", None)
        ports.append({
            "name": str(name),
            "oper": classify(oper_vals.values()),
            "admin": classify([admin_val]) if admin_val is not None else "up",
            "speed": _word(merged.get("speed")),
            "type": _word(body.get("type")),
            "raw_states": {k: _word(v) for k, v in oper_vals.items()},
        })
    return ports


def parse_interface_table(text):
    """Fallback for the human table printed by `nv show interface`."""
    lines = text.splitlines()
    header_idx = next((i for i, l in enumerate(lines) if re.match(r"^\s*Interface\b", l)), None)
    if header_idx is None:
        return []
    header = lines[header_idx]
    cols = [(m.group(0).strip().lower(), m.start()) for m in re.finditer(r"\S+(?: \S+)*", header)]
    bounds = [(name, start, cols[i + 1][1] if i + 1 < len(cols) else None) for i, (name, start) in enumerate(cols)]

    def pick(row, *names):
        for want in names:
            for name, start, end in bounds:
                if name == want:
                    return row[start:end].strip() if end else row[start:].strip()
        return ""

    ports = []
    for line in lines[header_idx + 1:]:
        if not line.strip() or set(line.strip()) <= {"-", " ", "="}:
            continue
        oper_fields = [pick(line, "oper status", "oper state", "state", "logical state"), pick(line, "physical state")]
        admin = pick(line, "admin status", "admin state")
        ports.append({
            "name": line.split()[0],
            "oper": classify(oper_fields),
            "admin": classify([admin]) if admin else "up",
            "speed": pick(line, "speed").lower(),
            "type": pick(line, "type").lower(),
            "raw_states": {"table": " / ".join(f for f in oper_fields if f)},
        })
    return ports


def is_data_port(name, os_type, s):
    pattern = getattr(s.switch, f"{os_type}_port_regex", "")
    return bool(pattern and re.match(pattern, name))


def port_sort_key(name):
    return [int(n) if n.isdigit() else n for n in re.split(r"(\d+)", name)]


HINT_RULES = [
    (r"not present|no module|module absent|unplugged|no cable|cable is not connected|not connected",
     "No cable/transceiver detected - check cabling, reseat or replace module"),
    (r"loss of signal|\blos\b|no signal|signal not detected|signal detect.*(no|false)",
     "Loss of signal - check far end is up, fiber polarity, clean connectors"),
    (r"negotiation fail|auto-?neg.*fail|speed mismatch|speed.*not supported",
     "Speed/auto-negotiation problem - make both ends match speed/FEC"),
    (r"signal integrity|high ber|ber .*exceed|symbol error",
     "Signal integrity / BER issue - suspect cable or transceiver, check counters"),
    (r"temperature (high|alarm)|over.?temp|high temperature",
     "Transceiver temperature alarm - check airflow / module"),
    (r"(rx|tx) power.*(low|alarm)|power (low|high) alarm",
     "Optical power alarm - check fiber, connectors, module"),
    (r"unsupported cable|cable not supported|unsupported module",
     "Unsupported cable/module for this port speed"),
    (r"remote fault|partner fault|far.end fault",
     "Remote/partner fault reported - check the far-end device"),
]


def analyze_port(port, outputs):
    hints = []
    if port["admin"] == "down":
        hints.append("Port is administratively down (shutdown in config)")
    if port["oper"] == "init":
        hints.append("Physical link is up but logical state is Init/Armed - "
                     "Subnet Manager (UFM/opensm) has not activated the port")
    blob = "\n".join(out for out in outputs.values() if not out.startswith("[command failed")).lower()
    for pattern, hint in HINT_RULES:
        if re.search(pattern, blob) and hint not in hints:
            hints.append(hint)
    for cmd, out in outputs.items():
        if "diagnostics" in cmd and not out.startswith("[command failed"):
            for line in out.splitlines()[:40]:
                if re.search(r"(status|code|description|reason)", line, re.I) and len(line.strip()) > 3:
                    hints.append("link diagnostics: " + re.sub(r"\s{2,}", " ", line.strip()))
    if not hints:
        hints.append("No specific cause found - review raw diag output")
    return hints


# ------------------------------------------------------------------ device checks


def check_os(sess, device, report):
    res = sess.run("nv show system -o json")
    version, info = "", {}
    try:
        info = extract_json(res.stdout)
        for key in ("build", "version", "image", "product-release"):
            val = info.get(key)
            if isinstance(val, dict):
                val = val.get("version") or val.get("current") or next(iter(val.values()), "")
            if val:
                version = str(val)
                break
    except (ValueError, AttributeError):
        text = sess.run("nv show system").stdout
        m = re.search(r"^\s*(build|version)\s+(.+)$", text, re.I | re.M)
        version = m.group(2).strip() if m else ""

    detail = f"{device.os} {version or 'version unknown'}"
    if isinstance(info, dict) and info.get("hostname"):
        detail += f", hostname {info['hostname']}"
    status = PASS if version else WARN
    if device.expected_os_version and device.expected_os_version not in version:
        status, detail = FAIL, detail + f" (expected '{device.expected_os_version}')"
    report.add("OS", status, detail, version=version)


def get_ports(sess):
    res = sess.run("nv show interface -o json")
    ports = []
    if res.ok:
        try:
            ports = parse_interface_json(extract_json(res.stdout))
        except ValueError:
            ports = []
    if not ports:
        ports = parse_interface_table(sess.run("nv show interface").stdout)
    if not ports:
        raise RuntimeError(f"could not parse `nv show interface`: {res.text[:200]}")
    return ports


def data_ports(all_ports, device, s):
    ports = [p for p in all_ports if is_data_port(p["name"], device.os, s)]
    if not ports:  # unknown naming scheme - everything except obvious mgmt/loopback
        ports = [p for p in all_ports if p["name"] not in ("lo", "eth0", "mgmt", "ib0")]
    return sorted(ports, key=lambda p: port_sort_key(p["name"]))


def diag_port(sess, device, port, s):
    outputs = {}
    for template in getattr(s.switch, f"{device.os}_diag_commands", []):
        cmd = template.format(port=safe_token(port["name"]))
        res = sess.run_any(cmd)
        outputs[cmd] = res.stdout if res.ok else f"[command failed rc={res.rc}] {res.text}"
    return PortDiag(port=port["name"], state=port["oper"], admin=port["admin"],
                    hints=analyze_port(port, outputs), outputs=outputs)


def check_ports(sess, device, report, s, include_admin_down=False, max_diag=None, only_ports=None):
    max_diag = s.checks.max_diag_ports if max_diag is None else max_diag
    ports = data_ports(get_ports(sess), device, s)
    patterns = only_ports or device.port_patterns
    monitored = [p for p in ports if not patterns or any(fnmatch.fnmatch(p["name"], pat) for pat in patterns)]
    report.ports = ports

    counts = {}
    for p in monitored:
        key = "admin-down" if p["admin"] == "down" else p["oper"]
        counts[key] = counts.get(key, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))

    problems = [p for p in monitored if p["oper"] != "up" and (p["admin"] != "down" or include_admin_down)]
    down = [p for p in problems if p["oper"] in ("down", "unknown")]
    init = [p for p in problems if p["oper"] == "init"]

    scope = f"{len(monitored)} monitored" + (f" of {len(ports)}" if patterns else "")
    if down:
        status = FAIL if patterns else WARN  # without a port list, unused down ports are expected
    elif init:
        status = WARN
    else:
        status = PASS
    report.add("Ports", status, f"{scope}: {summary}", down=[p["name"] for p in down], init=[p["name"] for p in init])

    for port in problems[:max_diag]:
        diag = guarded(report, f"Diag {port['name']}", diag_port, sess, device, port, s)
        report.port_diags.append(diag or PortDiag(port["name"], port["oper"], port["admin"], ["diag crashed"]))
    if len(problems) > max_diag:
        report.add("Port diag", INFO, f"diagnosed first {max_diag} of {len(problems)} problem ports (--max-diag)")


def run_switch_checks(device, s, include_admin_down=False, max_diag=None, only_ports=None):
    report = DeviceReport.for_device(device)
    ok = netutil.ping(device.mgmt_address)
    report.add("Mgmt ping", PASS if ok else FAIL, f"{device.mgmt_address} {'reachable' if ok else 'no reply'}")
    try:
        with open_session(device, s) as sess:
            report.add("SSH", PASS, f"{device.username}@{device.mgmt_address}")
            guarded(report, "OS", check_os, sess, device, report)
            guarded(report, "Ports", check_ports, sess, device, report, s,
                    include_admin_down=include_admin_down, max_diag=max_diag, only_ports=only_ports)
    except Exception as exc:  # noqa: BLE001
        report.add("SSH", FAIL, f"{device.username}@{device.mgmt_address}: {type(exc).__name__}: {exc}")
    return report
