"""Data objects shared across collectors, analysis and outputs."""

import time
from dataclasses import dataclass, field

PASS, INFO, WARN, FAIL = "PASS", "INFO", "WARN", "FAIL"
SEVERITY = {PASS: 0, INFO: 0, WARN: 1, FAIL: 2}
STATUS_VALUE = {PASS: 0, INFO: 0, WARN: 1, FAIL: 2}  # exported to Prometheus


def worst(statuses):
    top = max((SEVERITY[s] for s in statuses), default=0)
    return {0: PASS, 1: WARN, 2: FAIL}[top]


# --------------------------------------------------------------------------- health checks


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    data: dict = field(default_factory=dict)


@dataclass
class PortDiag:
    port: str
    state: str
    admin: str
    hints: list = field(default_factory=list)
    outputs: dict = field(default_factory=dict)


@dataclass
class DeviceReport:
    name: str
    os: str
    role: str
    address: str
    checks: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    port_diags: list = field(default_factory=list)

    @classmethod
    def for_device(cls, device):
        return cls(device.name, device.os, device.role, device.mgmt_address)

    def add(self, name, status, detail="", **data):
        self.checks.append(Check(name, status, detail, data))

    @property
    def status(self):
        return worst(c.status for c in self.checks)

    def problems(self):
        return [c for c in self.checks if c.status in (WARN, FAIL)]


def guarded(report, name, func, *args, **kwargs):
    """Run one check; an exception becomes a FAIL entry instead of aborting the device."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - every failure must be recorded
        report.add(name, FAIL, f"check crashed: {type(exc).__name__}: {exc}")
        return None


# --------------------------------------------------------------------------- port metrics


@dataclass
class PortSample:
    device: str
    role: str                     # switch | server
    os: str
    port: str
    aliases: list = field(default_factory=list)   # other names for the same port, e.g. "mlx5_0/1"
    oper: str = "unknown"         # up | down | init | unknown
    admin: str = "unknown"
    speed: str = ""
    media: str = "unknown"        # optical | copper | absent | unknown
    counters: dict = field(default_factory=dict)  # canonical name -> cumulative value
    ber: dict = field(default_factory=dict)       # effective_ber / raw_ber / symbol_ber
    dom: dict = field(default_factory=dict)       # rx_power_dbm / tx_power_dbm / tx_bias_ma / temperature_c / voltage_v -> [lanes]
    thresholds: dict = field(default_factory=dict)  # e.g. rx_power_dbm_low_warn
    alarms: list = field(default_factory=list)
    module: dict = field(default_factory=dict)    # vendor / part / identifier
    errors: list = field(default_factory=list)    # collection problems
    timestamp: float = field(default_factory=time.time)

    def names(self):
        return {self.port, *self.aliases}


@dataclass
class LinkResult:
    link_id: str
    a_device: str
    a_port: str
    b_device: str = ""
    b_port: str = ""
    media: str = "unknown"
    status: str = PASS
    component: str = "none"       # none | switch_port | switch_transceiver | node_port | node_transceiver |
                                  # cable | cable_or_far_end | subnet_manager | ambiguous | unknown
    location: str = ""
    summary: str = ""
    action: str = ""
    evidence: list = field(default_factory=list)
    mapped: bool = True


@dataclass
class Finding:
    """A problem that may become a Jira ticket."""
    key: str          # stable identity used for de-duplication
    device: str
    severity: str
    title: str
    detail: str
