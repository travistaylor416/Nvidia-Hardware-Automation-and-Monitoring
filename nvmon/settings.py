"""
Configuration loader.

Precedence (lowest -> highest):
    1. defaults in this file
    2. TOML file:  --config PATH, else $NVMON_CONFIG, else ./nvmon.toml if it exists
    3. environment variables:  NVMON_<SECTION>_<KEY>   e.g. NVMON_JIRA_PROJECT_KEY=NET
    4. CLI flags

Secrets are NEVER read from the TOML file (the loader refuses keys that look like secrets).
They come only from the environment variables listed in SECRET_ENV, so the config file can be
committed to git / reviewed by security without exposing credentials.

Env value formats: lists are comma-separated (or a JSON array), dicts are JSON,
booleans accept 1/0/true/false/yes/no/on/off.
"""

import json
import logging
import os
import re
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

log = logging.getLogger(__name__)

SECRET_ENV = {
    "ssh_password": "NVMON_SSH_PASSWORD",            # also NVMON_SSH_PASSWORD_<NVOS|CUMULUS|UBUNTU>
    "jira_user": "NVMON_JIRA_USER",                  # Jira Cloud: account email
    "jira_token": "NVMON_JIRA_TOKEN",                # Cloud API token, or Server/DC personal access token
    "pushgateway_user": "NVMON_PUSHGATEWAY_USER",
    "pushgateway_password": "NVMON_PUSHGATEWAY_PASSWORD",
    "exporter_token": "NVMON_EXPORTER_TOKEN",        # bearer token required on /metrics when set
}
_SECRETISH = re.compile(r"(password|passwd|token|secret|api_key|apikey)$", re.I)


def secret(name, os_type=None):
    if name == "ssh_password" and os_type:
        value = os.environ.get(f"NVMON_SSH_PASSWORD_{os_type.upper()}")
        if value:
            return value
    return os.environ.get(SECRET_ENV[name]) or None


# --------------------------------------------------------------------------- sections


@dataclass
class General:
    inventory: str = "inventory.csv"
    links: str = "links.csv"            # cable map used for fault isolation (optional)
    report_dir: str = "reports"
    state_dir: str = "state"            # Jira de-dupe state
    workers: int = 8


@dataclass
class SSH:
    port: int = 22
    timeout: int = 10
    command_timeout: int = 60
    key_file: str = ""
    host_key_policy: str = "warn"       # auto | warn | reject   (use reject in production)
    known_hosts: str = ""               # extra known_hosts file to load
    username_ubuntu: str = "ubuntu"
    username_nvos: str = "admin"
    username_cumulus: str = "cumulus"


@dataclass
class Checks:
    expected_dns_servers: list = field(default_factory=list)
    dns_test_names: list = field(default_factory=list)
    bmc_lan_channel: int = 1
    bmc_tcp_ports: list = field(default_factory=lambda: [443])
    fabric_expected_mtu: int = 0        # 0 = don't check
    ping_count: int = 2
    ping_timeout: int = 2
    max_diag_ports: int = 64


@dataclass
class Switch:
    nvos_port_regex: str = r"^sw\d+p\d+(s\d+)?$"
    cumulus_port_regex: str = r"^swp\d+(s\d+)?$"
    # "sudo:" prefix = run through sudo.  {port} is substituted.
    nvos_diag_commands: list = field(default_factory=lambda: [
        "nv show interface {port}",
        "nv show interface {port} link",
        "nv show interface {port} link diagnostics",
        "nv show interface {port} counters",
        "nv show interface {port} transceiver",
    ])
    cumulus_diag_commands: list = field(default_factory=lambda: [
        "nv show interface {port}",
        "nv show interface {port} link",
        "nv show interface {port} pluggable",
        "nv show interface {port} counters",
        "sudo:l1-show {port}",
        "ip -d link show {port}",
    ])


@dataclass
class Metrics:
    # Each *_commands entry is a list of ALTERNATIVES: the first one that succeeds is used.
    # Placeholders: {port}  {hca}  {hca_port}
    nvos_counter_commands: list = field(default_factory=lambda: [
        "nv show interface {port} counters -o json",
        "nv show interface {port} link counters -o json",
    ])
    nvos_module_commands: list = field(default_factory=lambda: [
        "nv show interface {port} transceiver -o json",
        "nv show platform transceiver {port} -o json",
    ])
    cumulus_counter_commands: list = field(default_factory=lambda: ["ethtool -S {port}"])
    cumulus_module_commands: list = field(default_factory=lambda: ["sudo:ethtool -m {port}"])
    ubuntu_counter_commands: list = field(default_factory=lambda: ["ethtool -S {port}"])
    ubuntu_module_commands: list = field(default_factory=lambda: ["sudo:ethtool -m {port}"])
    # InfiniBand-mode HCA ports: counters come from sysfs; this adds DOM/BER (needs NVIDIA MFT).
    ubuntu_ib_module_commands: list = field(default_factory=lambda: ["sudo:mlxlink -d {hca} -p {hca_port} -m -c -e"])
    # NVOS shells may not allow `sh -c` loops, so run one SSH exec per command there.
    batch_nvos: bool = False
    batch_cumulus: bool = True
    batch_ubuntu: bool = True
    switch_ports: str = "monitored"     # all | monitored (Ports column + links.csv; all if neither set)
    server_all_rdma_ports: bool = True  # collect every HCA port, not only linked/fabric ones
    sample_interval: int = 0            # one-shot `metrics`: >0 takes two samples N s apart for deltas


@dataclass
class Thresholds:
    # Used when the transceiver does not report its own alarm/warning thresholds.
    rx_power_low_dbm: float = -10.0
    tx_power_low_dbm: float = -8.0
    temperature_high_c: float = 70.0
    effective_ber_max: float = 1e-12
    raw_ber_max: float = 1e-5
    symbol_ber_max: float = 1e-13
    error_delta_warn: int = 1           # new rx errors within one interval -> WARN
    error_delta_fail: int = 100         # -> FAIL
    cumulative_error_warn: int = 1000   # single sample (no delta): lifetime errors -> WARN
    link_flaps_warn: int = 1


@dataclass
class Prometheus:
    outputs: list = field(default_factory=lambda: ["http"])   # any of: http, textfile, pushgateway
    listen_address: str = "127.0.0.1"   # set 0.0.0.0 only behind a firewall / with exporter token
    listen_port: int = 9877
    interval: int = 60                  # seconds between collections in `exporter` mode
    metric_prefix: str = "nvmon"
    textfile_path: str = ""             # e.g. /var/lib/node_exporter/textfile_collector/nvmon.prom
    pushgateway_url: str = ""
    pushgateway_job: str = "nvmon"
    include_health_checks: bool = True
    health_check_every: int = 5         # run full health checks every N collection cycles
    verify_tls: bool = True
    ca_bundle: str = ""


@dataclass
class Jira:
    enabled: bool = False
    dry_run: bool = True                # print payloads only - flip to false after review
    url: str = ""                       # https://yourcompany.atlassian.net or https://jira.corp.local
    deployment: str = "cloud"           # cloud (email + API token) | server (Server/DC personal access token)
    api_version: str = "2"
    project_key: str = ""
    issue_type: str = "Task"
    labels: list = field(default_factory=lambda: ["nvmon"])
    components: list = field(default_factory=list)
    priority_map: dict = field(default_factory=lambda: {"FAIL": "High", "WARN": "Medium"})
    set_priority: bool = True
    min_severity: str = "FAIL"          # FAIL | WARN
    group_by: str = "device"            # device = one ticket per device, finding = one per check/link
    dedupe: bool = True                 # reuse an open ticket instead of creating a duplicate
    comment_on_change: bool = True      # add a comment when an open ticket's findings change
    assignee: str = ""                  # Cloud accountId or Server username
    extra_fields: dict = field(default_factory=dict)   # custom fields, e.g. {"customfield_10010": "x"}
    summary_prefix: str = "[nvmon]"
    max_issues_per_run: int = 20        # safety valve against ticket storms
    verify_tls: bool = True
    ca_bundle: str = ""
    timeout: int = 15


@dataclass
class Settings:
    general: General = field(default_factory=General)
    ssh: SSH = field(default_factory=SSH)
    checks: Checks = field(default_factory=Checks)
    switch: Switch = field(default_factory=Switch)
    metrics: Metrics = field(default_factory=Metrics)
    thresholds: Thresholds = field(default_factory=Thresholds)
    prometheus: Prometheus = field(default_factory=Prometheus)
    jira: Jira = field(default_factory=Jira)
    config_file: str = ""

    def username_for(self, os_type):
        return getattr(self.ssh, f"username_{os_type}", "")

    def to_dict(self):
        data = asdict(self)
        data["secrets_present"] = {name: bool(os.environ.get(env)) for name, env in SECRET_ENV.items()}
        return data


SECTIONS = [f.name for f in fields(Settings) if f.name != "config_file"]

# --------------------------------------------------------------------------- loading


def _coerce(value, default):
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(value)
    if isinstance(default, float):
        return float(value)
    if isinstance(default, list):
        if isinstance(value, list):
            items = value
        elif str(value).strip().startswith("["):
            items = json.loads(value)
        else:
            items = [v.strip() for v in str(value).split(",") if v.strip()]
        if default and isinstance(default[0], int):
            items = [int(i) for i in items]
        return items
    if isinstance(default, dict):
        return value if isinstance(value, dict) else json.loads(value)
    return str(value)


def _apply(section_obj, key, value, origin):
    if _SECRETISH.search(key):
        raise ValueError(f"{origin}: '{key}' looks like a secret - set it via environment variable instead")
    if not hasattr(section_obj, key):
        log.warning("%s: unknown setting '%s' ignored", origin, key)
        return
    setattr(section_obj, key, _coerce(value, getattr(section_obj, key)))


def load(path=None, environ=None):
    environ = os.environ if environ is None else environ
    settings = Settings()

    path = path or environ.get("NVMON_CONFIG") or ("nvmon.toml" if Path("nvmon.toml").exists() else None)
    if path:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        for section, values in data.items():
            if section not in SECTIONS or not isinstance(values, dict):
                log.warning("%s: unknown section [%s] ignored", path, section)
                continue
            for key, value in values.items():
                _apply(getattr(settings, section), key, value, f"{path} [{section}]")
        settings.config_file = str(path)

    for section in SECTIONS:
        obj = getattr(settings, section)
        for f in fields(obj):
            env = f"NVMON_{section.upper()}_{f.name.upper()}"
            if env in environ:
                setattr(obj, f.name, _coerce(environ[env], getattr(obj, f.name)))
    return settings


_current = None


def current():
    global _current
    if _current is None:
        _current = load()
    return _current


def set_current(settings):
    global _current
    _current = settings
    return settings
