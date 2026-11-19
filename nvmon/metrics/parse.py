"""
Turn raw command output into canonical port metrics.

One generic parser handles every source we use, because vendor field names drift between releases:
    nv show interface <port> counters/transceiver -o json   (NVOS / Cumulus)
    ethtool -S <port>                                         (Cumulus switchd counters, mlx5 *_phy counters)
    ethtool -m <port>                                         (module EEPROM: DOM, thresholds, alarms, media)
    mlxlink -d <hca> -m -c -e                                 (NVIDIA MFT: BER, DOM per lane)
    /sys/class/infiniband/<hca>/ports/<n>/counters/*          (IB HCA error counters)

Every (key, value) pair is matched against the rules below by normalized key name.  To support a new
field name, add a regex here and a test case in tests/test_metrics.py.
"""

import json
import math
import re

ANSI = re.compile(r"\x1b\[[0-9;]*m")
NUM = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?", re.I)

# Canonical counter name -> regex on the normalized key.  Order matters (first match wins).
COUNTER_RULES = [
    ("fec_uncorrectable", r"uncorrect"),
    ("fec_corrected", r"correct(ed|able)"),
    ("crc_errors", r"crc|fcs"),
    ("symbol_errors", r"symbol_?err"),
    ("link_error_recovery", r"link_?err\w*recover"),
    ("link_downed", r"link_?down|carrier_?changes"),
    ("local_link_integrity_errors", r"local_?link_?integrity"),
    ("excessive_buffer_overrun", r"excessive_?buffer_?overrun"),
    ("rx_remote_phy_errors", r"remote_?phys"),
    ("rx_errors", r"^(port_)?(rcv|rx|in)_?err(or)?s?$|^hwifinerrors$|^counters_(rx|in)_errors$"),
    ("tx_discards", r"xmit_?discard|(tx|out)_?discard"),
]

# Counters that indicate errors on the RECEIVE side of a port (used for fault isolation).
RX_ERROR_COUNTERS = ("crc_errors", "symbol_errors", "fec_uncorrectable", "rx_errors",
                     "local_link_integrity_errors", "rx_remote_phy_errors")

DOM_UNITS = {"rx_power_dbm": "dBm", "tx_power_dbm": "dBm", "tx_bias_ma": "mA",
             "temperature_c": "C", "voltage_v": "V"}


def norm_key(key):
    return re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")


def flatten(obj, prefix=""):
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            out += flatten(v, f"{prefix}.{k}" if prefix else str(k))
        return out
    if isinstance(obj, list):
        out = []
        for i, v in enumerate(obj):
            out += flatten(v, f"{prefix}.{i}")
        return out
    return [(prefix, obj)]


def kv_lines(text):
    pairs = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith(("#", "---", "===")):
            continue
        if ":" in line:
            key, val = line.split(":", 1)
        else:
            m = re.match(r"^\s*(\S.*?)\s{2,}(\S.*)$", line)
            if not m:
                continue
            key, val = m.groups()
        if key.strip():
            pairs.append((key.strip(), val.strip()))
    return pairs


def parse_any(text):
    text = ANSI.sub("", text or "").strip()
    if text[:1] in "{[":
        try:
            return flatten(json.loads(text))
        except ValueError:
            pass
    return kv_lines(text)


def parse_number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = NUM.search(str(value).replace(",", ""))
    return float(m.group(0)) if m else None


def mw_to_dbm(mw):
    return round(10 * math.log10(mw), 2) if mw and mw > 0 else -40.0


def parse_power_dbm(value, key=""):
    text = str(value).lower()
    if "-inf" in text:
        return -40.0
    m = re.search(r"([-+]?\d+\.?\d*(?:e[-+]?\d+)?)\s*dbm", text)
    if m:
        return float(m.group(1))
    m = re.search(r"([-+]?\d+\.?\d*(?:e[-+]?\d+)?)\s*mw", text)
    if m:
        return mw_to_dbm(float(m.group(1)))
    num = parse_number(value)
    if num is None:
        return None
    return mw_to_dbm(num) if "mw" in key else num


def dom_quantity(k):
    tokens = set(k.split("_"))
    if "power" in tokens or "pwr" in tokens:
        if tokens & {"rx", "rcv", "rcvr", "receive", "receiver", "received"} or "receiv" in k:
            return "rx_power_dbm"
        if tokens & {"tx", "transmit", "transmitter", "output", "laser"} or "transmit" in k:
            return "tx_power_dbm"
        return None
    if "bias" in tokens:
        return "tx_bias_ma"
    if "temperature" in tokens or "temp" in tokens:
        return "temperature_c"
    if "voltage" in tokens or "vcc" in tokens or "volt" in tokens:
        return "voltage_v"
    return None


def lane_of(raw_key):
    k = str(raw_key).lower()
    m = re.search(r"(?:channel|lane|ch)[\s_.\-]*(\d+)", k)
    if m:
        return int(m.group(1))
    m = re.search(r"\.(\d+)(?:\.|$)", k)
    return int(m.group(1)) if m else None


def detect_media(texts):
    blob = " ".join(texts).lower()
    if re.search(r"not present|absent|no module|unplugged", blob):
        return "absent"
    if re.search(r"copper|\bdac\b|twinax|passive cable|active cable \(copper|acc\b", blob):
        return "copper"
    if re.search(r"optic|vcsel|\bnm\b|\d+ ?nm|\baoc\b|\bsr\d?\b|\bdr\d?\b|\bfr\d?\b|\blr\d?\b|laser|fiber|fibre|smf|mmf", blob):
        return "optical"
    return "unknown"


def canonicalize(text):
    """Return dict(counters, ber, dom, thresholds, alarms, module, media) from any supported output."""
    out = {"counters": {}, "ber": {}, "dom": {}, "thresholds": {}, "alarms": [], "module": {}, "media": "unknown"}
    lanes = {}
    media_texts = []

    for raw_key, value in parse_any(text):
        segs = [norm_key(s) for s in str(raw_key).split(".") if s != ""]
        k_full = norm_key(raw_key)
        k_last = segs[-1] if segs else k_full
        k_two = "_".join(segs[-2:]) if len(segs) >= 2 else k_last
        sval = str(value).strip()
        lval = sval.lower()

        # module identity / media
        if re.search(r"vendor_?name$|^vendor$|manufacturer", k_last):
            out["module"].setdefault("vendor", sval)
            continue
        if re.search(r"(vendor_)?(pn|part_?(number|no))$", k_last):
            out["module"].setdefault("part", sval)
            continue
        if re.search(r"identifier|form_factor", k_last):
            out["module"].setdefault("identifier", sval)
            media_texts.append(sval)
            continue
        if re.search(r"transmitter_technology|cable_type|cable_technology|media|module_type|connector|"
                     r"compliance|cable_length|ethernet_type", k_full):
            media_texts.append(sval)
            continue
        if re.search(r"present|module_status|module_state|^status$", k_last) and re.search(r"not present|absent|unplugged", lval):
            media_texts.append(lval)
            continue

        # module-provided thresholds
        if "threshold" in k_full:
            q = dom_quantity(k_full)
            hl = "high" if "high" in k_full else "low" if "low" in k_full else None
            aw = "alarm" if "alarm" in k_full else "warn" if "warn" in k_full else None
            if q and hl and aw:
                v = parse_power_dbm(sval, k_full) if q.endswith("dbm") else parse_number(sval)
                if v is not None:
                    out["thresholds"][f"{q}_{hl}_{aw}"] = v
            continue

        # alarm / warning flags
        if re.search(r"(alarm|warning)", k_full):
            if lval in ("on", "yes", "true", "asserted", "set"):
                out["alarms"].append(str(raw_key).strip())
            continue

        # BER
        if "ber" in k_last.split("_"):
            name = ("effective_ber" if "eff" in k_last else "raw_ber" if "raw" in k_last
                    else "symbol_ber" if "symbol" in k_last else "ber")
            v = parse_number(sval)
            if v is not None:
                out["ber"].setdefault(name, v)
            continue

        # DOM
        q = dom_quantity(k_full)
        if q:
            if "," in sval:  # mlxlink style: one value per lane, comma-separated
                parse = (lambda x: parse_power_dbm(x, k_full)) if q.endswith("dbm") else parse_number
                for i, v in enumerate(parse(x) for x in sval.split(",")):
                    if v is not None:
                        lanes.setdefault(q, {})[i] = v
                continue
            v = parse_power_dbm(sval, k_full) if q.endswith("dbm") else parse_number(sval)
            if v is not None:
                lane = lane_of(raw_key)
                lanes.setdefault(q, {})[lane if lane is not None else len(lanes.get(q, {}))] = v
            continue

        # counters
        for name, rx in COUNTER_RULES:
            if re.search(rx, k_last) or re.search(rx, k_two):
                if NUM.fullmatch(sval.replace(",", "")):  # counters must be plain numbers
                    out["counters"].setdefault(name, float(sval.replace(",", "")))
                break

    for q, by_lane in lanes.items():
        out["dom"][q] = [by_lane[i] for i in sorted(by_lane)]
    out["media"] = detect_media(media_texts)
    return out


def parse_ib_sysfs(text):
    """`grep -H . /sys/class/infiniband/*/ports/*/{state,phys_state,rate,link_layer,counters/*}`
    -> {("mlx5_0", "1"): {"state": "4: ACTIVE", ..., "counters_text": "symbol_error: 0\n..."}}"""
    ports = {}
    for line in text.splitlines():
        m = re.match(r"^/sys/class/infiniband/([^/]+)/ports/(\d+)/(counters/)?([^:]+):(.*)$", line.strip())
        if not m:
            continue
        hca, port, is_counter, name, value = m.groups()
        entry = ports.setdefault((hca, port), {"counters_text": ""})
        if is_counter:
            entry["counters_text"] += f"{name}: {value.strip()}\n"
        else:
            entry[name] = value.strip()
    return ports


def ib_state(state, phys_state=""):
    s, p = state.lower(), phys_state.lower()
    if "active" in s:
        return "up"
    if "init" in s or "armed" in s:
        return "init"
    if "down" in s or "polling" in p or "disabled" in p:
        return "down"
    return "unknown"
