"""
Link fault isolation.

For every cable in links.csv we look at BOTH ends and score which component is most likely at fault:

    signal                                             points at
    -------------------------------------------------  ------------------------------------------
    no module / cable detected at one end              that end's transceiver / cable
    Tx power low at X                                  X's transceiver (laser failing)
    Rx power low at Y while X's Tx power is normal      the fiber / connectors between X and Y
    module over temperature at X                       X's transceiver
    rx errors / high BER at both ends                  the shared cable / connectors
    rx errors at Y only, light levels normal           ambiguous: X transmitter, Y receiver or cable
      ...on copper (DAC)                               cable first, then either port
    logical state Init/Armed (InfiniBand)              Subnet Manager, not the physical layer

Errors are judged on counter DELTAS between two samples (exporter cycles or `metrics --interval`).
With a single sample only lifetime counters are available, so they can only raise a WARN.

Ports that are not in links.csv get a single-ended verdict (e.g. "cable or far end").
"""

from collections import defaultdict
from dataclasses import dataclass, field

from ..models import FAIL, INFO, PASS, WARN, LinkResult, worst
from .parse import RX_ERROR_COUNTERS

ACTIONS = {
    "switch_transceiver": "Reseat, then replace the transceiver/AOC end on the switch port; check airflow if hot.",
    "node_transceiver": "Reseat, then replace the transceiver/AOC end on the server NIC/HCA; check airflow if hot.",
    "cable": "Clean and inspect connectors at both ends, then replace the fiber/DAC.",
    "cable_or_far_end": "Check the far-end device is up and transmitting, then clean/replace the fiber.",
    "switch_port": "Move the cable to a known-good switch port; if the fault stays with the port, RMA the switch.",
    "node_port": "Move the cable to another NIC/HCA port; if the fault stays with the port, replace the adapter.",
    "subnet_manager": "Physical layer is up - check UFM/opensm is running and has swept this port.",
    "ambiguous": "Swap the transceivers end-for-end (or swap in a known-good cable) and watch which way the fault moves.",
    "unknown": "Review the raw counters/DOM for both ends; add the link to links.csv for correlation.",
    "none": "",
}


def counter_deltas(prev, cur):
    if prev is None:
        return None
    out = {}
    for key, value in cur.counters.items():
        if key in prev.counters:
            before = prev.counters[key]
            out[key] = value - before if value >= before else value  # counter cleared/wrapped
    return out


@dataclass
class Side:
    sample: object
    label: str                    # "A" / "B"
    rx_low: str | None = None     # None | warn | alarm
    rx_min: float | None = None
    tx_low: str | None = None
    tx_min: float | None = None
    hot: str | None = None
    temp: float | None = None
    err_level: str | None = None  # None | WARN | FAIL
    rx_errors: float = 0
    cumulative: bool = True
    ber_high: list = field(default_factory=list)
    flaps: float | None = None

    @property
    def name(self):
        return f"{self.sample.device}:{self.sample.port}"

    @property
    def kind(self):
        return "switch" if self.sample.role == "switch" else "node"


def _low(sample, q, fallback):
    values = sample.dom.get(q) or []
    if not values:
        return None, None
    low = min(values)
    alarm = sample.thresholds.get(f"{q}_low_alarm")
    warn = sample.thresholds.get(f"{q}_low_warn")
    if low <= -30 or (alarm is not None and low <= alarm):
        return "alarm", low
    if (warn is not None and low <= warn) or (warn is None and alarm is None and low <= fallback):
        return "warn", low
    return None, low


def evaluate(sample, delta, th, label="A"):
    side = Side(sample, label)
    side.rx_low, side.rx_min = _low(sample, "rx_power_dbm", th.rx_power_low_dbm)
    side.tx_low, side.tx_min = _low(sample, "tx_power_dbm", th.tx_power_low_dbm)

    temps = sample.dom.get("temperature_c") or []
    if temps:
        side.temp = max(temps)
        alarm = sample.thresholds.get("temperature_c_high_alarm")
        warn = sample.thresholds.get("temperature_c_high_warn", th.temperature_high_c)
        side.hot = "alarm" if alarm is not None and side.temp >= alarm else "warn" if side.temp >= warn else None

    if delta is not None:
        side.cumulative = False
        side.rx_errors = sum(delta.get(c, 0) for c in RX_ERROR_COUNTERS)
        side.flaps = delta.get("link_downed")
        if side.rx_errors >= th.error_delta_fail:
            side.err_level = FAIL
        elif side.rx_errors >= th.error_delta_warn:
            side.err_level = WARN
    else:
        side.rx_errors = sum(sample.counters.get(c, 0) for c in RX_ERROR_COUNTERS)
        if side.rx_errors >= th.cumulative_error_warn:
            side.err_level = WARN

    limits = {"effective_ber": th.effective_ber_max, "raw_ber": th.raw_ber_max, "symbol_ber": th.symbol_ber_max}
    side.ber_high = [f"{k}={v:.1e}" for k, v in sample.ber.items() if k in limits and v > limits[k]]
    return side


def _fmt(v):
    return "n/a" if v is None else f"{v:.2f}"


def _describe(key, by_label, sides):
    """Internal score key ('A_transceiver', 'cable', ...) -> (exported component, human location)."""
    if "_" in key and key.split("_", 1)[0] in by_label:
        label, part = key.split("_", 1)
        side = by_label[label]
        if part == "transceiver":
            return f"{side.kind}_transceiver", f"transceiver at {side.name}"
        return f"{side.kind}_port", f"{'switch port' if side.kind == 'switch' else 'NIC/HCA port'} {side.name}"
    return key, {
        "cable": "cable/fiber between " + " and ".join(s.name for s in sides),
        "cable_or_far_end": f"cable or far end of {sides[0].name}",
        "subnet_manager": "InfiniBand Subnet Manager",
        "ambiguous": "between " + " and ".join(s.name for s in sides),
    }.get(key, "")


def _result_from_scores(result, scores, statuses, sides):
    by_label = {s.label: s for s in sides}
    result.status = worst(statuses) if statuses else PASS
    if not scores:
        result.component = "unknown" if result.status == FAIL else "none"
        result.location = ""
    else:
        top = max(scores.values())
        tied = sorted(c for c, v in scores.items() if v == top)
        if len(tied) == 1:
            result.component, result.location = _describe(tied[0], by_label, sides)
        else:
            result.component, result.location = _describe("ambiguous", by_label, sides)
            result.evidence.append("equally likely: " + ", ".join(_describe(t, by_label, sides)[1] for t in tied))
    result.action = ACTIONS.get(result.component, "")
    result.summary = (result.location or "no fault") + (f" ({result.evidence[0]})" if result.evidence else "")
    return result


def isolate_link(link, a, b):
    """a, b: evaluated Sides (either may be None if not collected)."""
    result = LinkResult(link.link_id, link.a_device, link.a_port, link.b_device, link.b_port, media=link.media or "unknown")
    if a is None or b is None:
        missing = [n for n, s in (("A", a), ("B", b)) if s is None]
        result.status, result.component = INFO, "unknown"
        result.summary = f"no metrics for end {' and '.join(missing)} (device unreachable or port not found)"
        present = a or b
        single = isolate_endpoint(present) if present else None
        if single and single.status != PASS:  # a healthy half-link can't prove the link is healthy
            result.status, result.component, result.evidence = single.status, single.component, single.evidence
            result.location, result.action = single.location, single.action
            result.summary = f"{result.summary}; single-ended: {single.summary}"
        return result

    if result.media == "unknown":
        result.media = next((m for m in (a.sample.media, b.sample.media) if m not in ("unknown", "absent")), "unknown")
    if "down" in (a.sample.admin, b.sample.admin):
        result.status, result.summary = INFO, "administratively down"
        return result

    scores, statuses, ev = defaultdict(int), [], result.evidence

    for side in (a, b):
        if side.sample.media == "absent":
            scores[f"{side.label}_transceiver"] += 5
            statuses.append(FAIL)
            ev.append(f"no module/cable detected at {side.name}")

    states = (a.sample.oper, b.sample.oper)
    if "init" in states:
        scores["subnet_manager"] += 3
        statuses.append(WARN)
        ev.append(f"logical state Init/Armed ({a.name}={states[0]}, {b.name}={states[1]})")
    elif states == ("down", "down"):
        statuses.append(FAIL)
        ev.append("link down at both ends")
    elif "up" in states and "down" in states:
        statuses.append(WARN)
        ev.append(f"state mismatch {a.name}={states[0]} {b.name}={states[1]} - check links.csv mapping")

    for tx, rx in ((a, b), (b, a)):
        if tx.tx_low:
            scores[f"{tx.label}_transceiver"] += 3
            statuses.append(FAIL if tx.tx_low == "alarm" else WARN)
            ev.append(f"Tx power low at {tx.name} ({_fmt(tx.tx_min)} dBm)")
        elif rx.rx_low:
            statuses.append(FAIL if rx.rx_low == "alarm" else WARN)
            if tx.tx_min is not None:
                scores["cable"] += 3
                ev.append(f"Rx power low at {rx.name} ({_fmt(rx.rx_min)} dBm) while {tx.name} Tx is normal "
                          f"({_fmt(tx.tx_min)} dBm) - light is lost in the fiber/connectors")
            else:
                scores["cable"] += 2
                scores[f"{tx.label}_transceiver"] += 1
                ev.append(f"Rx power low at {rx.name} ({_fmt(rx.rx_min)} dBm), {tx.name} Tx power unknown")

    for side in (a, b):
        if side.hot:
            scores[f"{side.label}_transceiver"] += 2
            statuses.append(FAIL if side.hot == "alarm" else WARN)
            ev.append(f"module temperature {side.temp:.1f} C at {side.name}")

    a_bad = a.err_level or a.ber_high
    b_bad = b.err_level or b.ber_high
    for side in (a, b):
        if side.err_level:
            statuses.append(side.err_level)
            kind = "lifetime" if side.cumulative else "new"
            ev.append(f"{int(side.rx_errors)} {kind} rx errors at {side.name}")
        if side.ber_high:
            statuses.append(WARN)
            ev.append(f"high BER at {side.name}: {', '.join(side.ber_high)}")
    if a_bad and b_bad:
        scores["cable"] += 2
        ev.append("errors in both directions - common element is the cable/connectors")
    elif a_bad or b_bad:
        rx, tx = (a, b) if a_bad else (b, a)
        if result.media == "copper":
            scores["cable"] += 2
            scores[f"{rx.label}_port"] += 1
            scores[f"{tx.label}_port"] += 1
        elif not (rx.rx_low or tx.tx_low):
            scores[f"{tx.label}_transceiver"] += 1
            scores[f"{rx.label}_transceiver"] += 1
            scores["cable"] += 1
        ev.append(f"errors only in direction {tx.name} -> {rx.name}")

    if a.flaps and b.flaps:
        scores["cable"] += 1
        statuses.append(WARN)
        ev.append(f"link flapped (A {int(a.flaps)}x, B {int(b.flaps)}x) this interval")
    for side in (a, b):
        if side.sample.alarms:
            statuses.append(WARN)
            ev.append(f"module alarms at {side.name}: {', '.join(side.sample.alarms[:4])}")

    return _result_from_scores(result, scores, statuses, [a, b])


def isolate_endpoint(side):
    smp = side.sample
    result = LinkResult(side.name, smp.device, smp.port, media=smp.media, mapped=False)
    scores, statuses, ev = defaultdict(int), [], result.evidence
    own = f"{side.label}_transceiver"
    if smp.oper == "init":
        scores["subnet_manager"] += 3
        statuses.append(WARN)
        ev.append("logical state Init/Armed")
    if side.tx_low:
        scores[own] += 3
        statuses.append(FAIL if side.tx_low == "alarm" else WARN)
        ev.append(f"Tx power low ({_fmt(side.tx_min)} dBm)")
    if side.rx_low:
        scores["cable_or_far_end"] += 3
        statuses.append(FAIL if side.rx_low == "alarm" else WARN)
        ev.append(f"Rx power low ({_fmt(side.rx_min)} dBm)")
    if side.hot:
        scores[own] += 2
        statuses.append(FAIL if side.hot == "alarm" else WARN)
        ev.append(f"module temperature {side.temp:.1f} C")
    if side.err_level or side.ber_high:
        scores["ambiguous"] += 1
        statuses.append(side.err_level or WARN)
        ev.append(f"{int(side.rx_errors)} {'lifetime' if side.cumulative else 'new'} rx errors"
                  + (f", {', '.join(side.ber_high)}" if side.ber_high else "")
                  + " - add this link to links.csv to isolate")
    if smp.alarms:
        statuses.append(WARN)
        ev.append("module alarms: " + ", ".join(smp.alarms[:4]))
    return _result_from_scores(result, scores, statuses, [side])


def analyze(samples, links, th, previous=None):
    """samples: current PortSamples; previous: {(device, port): PortSample} from the last cycle."""
    previous = previous or {}
    index = {}
    for smp in samples:
        for name in smp.names():
            index[(smp.device.lower(), name.lower())] = smp

    def side_for(device, port, label):
        smp = index.get((device.lower(), port.lower()))
        if smp is None:
            return None
        return evaluate(smp, counter_deltas(previous.get((smp.device, smp.port)), smp), th, label)

    results, mapped = [], set()
    for link in links:
        a = side_for(link.a_device, link.a_port, "A")
        b = side_for(link.b_device, link.b_port, "B")
        for side in (a, b):
            if side:
                mapped.add(id(side.sample))
        results.append(isolate_link(link, a, b))

    for smp in samples:
        if id(smp) in mapped or smp.oper not in ("up", "init"):
            continue  # unmapped + down = usually an unused port; health checks already report it
        single = isolate_endpoint(evaluate(smp, counter_deltas(previous.get((smp.device, smp.port)), smp), th))
        if single.status != PASS:
            results.append(single)
    return results
