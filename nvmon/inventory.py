"""
Inventory (devices) and link map (cables) CSV loading.

inventory.csv columns (case-insensitive; Name, OS, Mgmt Address required):
    Name, Role, OS, Mgmt Address, Hostname, BMC Address, Fabric Addresses, Ports,
    Expected OS Version, Username, Location

    OS                   ubuntu | nvos | cumulus   (aliases: dgx os, cl, cumulus linux, nv-os)
    Fabric Addresses     servers: ';'-separated "10.100.0.11/24" or "ens1f0np0=10.100.0.11/24"
    Ports                switches: ';'-separated globs of ports that must be up (blank = all)

links.csv columns (one row per cable; used to correlate both ends of a link):
    A Device, A Port, B Device, B Port, Media (optional: optical|copper), Notes
    Server ports may be a netdev (ens1f0np0) or an HCA port (mlx5_0/1).
"""

import csv
from dataclasses import dataclass, field
from pathlib import Path

from . import settings as settings_mod

OS_ALIASES = {
    "ubuntu": "ubuntu", "dgx os": "ubuntu", "dgxos": "ubuntu", "dgx": "ubuntu", "linux": "ubuntu",
    "nvos": "nvos", "nv-os": "nvos", "nvidia nvos": "nvos",
    "cumulus": "cumulus", "cumulus linux": "cumulus", "cl": "cumulus",
}
ROLE_FOR_OS = {"ubuntu": "server", "nvos": "switch", "cumulus": "switch"}


@dataclass
class FabricAddress:
    ip: str
    prefix: int | None = None
    interface: str | None = None

    @classmethod
    def parse(cls, text):
        text = text.strip()
        iface = None
        if "=" in text:
            iface, text = (part.strip() for part in text.split("=", 1))
        prefix = None
        if "/" in text:
            text, pfx = text.split("/", 1)
            prefix = int(pfx)
        return cls(ip=text.strip(), prefix=prefix, interface=iface or None)

    def __str__(self):
        s = self.ip + (f"/{self.prefix}" if self.prefix is not None else "")
        return f"{self.interface}={s}" if self.interface else s


@dataclass
class Device:
    name: str
    os: str
    role: str
    mgmt_address: str
    hostname: str = ""
    bmc_address: str = ""
    fabric_addresses: list = field(default_factory=list)
    port_patterns: list = field(default_factory=list)
    expected_os_version: str = ""
    username: str = ""
    location: str = ""

    @property
    def is_server(self):
        return self.role == "server"

    @property
    def is_switch(self):
        return self.role == "switch"


@dataclass
class Link:
    a_device: str
    a_port: str
    b_device: str
    b_port: str
    media: str = ""
    notes: str = ""

    @property
    def link_id(self):
        return f"{self.a_device}:{self.a_port}<->{self.b_device}:{self.b_port}"

    def ports_for(self, device_name):
        out = []
        if self.a_device.lower() == device_name.lower():
            out.append(self.a_port)
        if self.b_device.lower() == device_name.lower():
            out.append(self.b_port)
        return out


def _split(value):
    return [v.strip() for v in (value or "").replace(",", ";").split(";") if v.strip()]


def _rows(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for line_no, row in enumerate(csv.DictReader(fh), start=2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            values = [v for v in row.values() if v]
            if not values or values[0].startswith("#"):
                continue
            yield line_no, row


def normalize_os(value):
    key = (value or "").strip().lower()
    if key not in OS_ALIASES:
        raise ValueError(f"unsupported OS '{value}' (use ubuntu, nvos or cumulus)")
    return OS_ALIASES[key]


def device_from_row(row, settings=None):
    settings = settings or settings_mod.current()
    row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
    os_type = normalize_os(row.get("os"))
    name = row.get("name") or row.get("device name")
    if not name:
        raise ValueError("missing Name")
    mgmt = row.get("mgmt address") or row.get("device address") or row.get("address")
    if not mgmt:
        raise ValueError(f"{name}: missing Mgmt Address")
    return Device(
        name=name,
        os=os_type,
        role=(row.get("role") or ROLE_FOR_OS[os_type]).lower(),
        mgmt_address=mgmt,
        hostname=row.get("hostname") or name,
        bmc_address=row.get("bmc address", ""),
        fabric_addresses=[FabricAddress.parse(f) for f in _split(row.get("fabric addresses"))],
        port_patterns=_split(row.get("ports")),
        expected_os_version=row.get("expected os version", ""),
        username=row.get("username") or settings.username_for(os_type),
        location=row.get("location", ""),
    )


def load_inventory(path, settings=None):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"inventory not found: {path} (copy inventory.example.csv to start)")
    devices, errors = [], []
    for line_no, row in _rows(path):
        try:
            devices.append(device_from_row(row, settings))
        except ValueError as exc:
            errors.append(f"{path.name} line {line_no}: {exc}")
    return devices, errors


def load_links(path):
    path = Path(path) if path else None
    if not path or not path.exists():
        return [], []
    links, errors = [], []
    for line_no, row in _rows(path):
        need = [row.get(k, "") for k in ("a device", "a port", "b device", "b port")]
        if not all(need):
            errors.append(f"{path.name} line {line_no}: needs A Device, A Port, B Device, B Port")
            continue
        links.append(Link(*need, media=row.get("media", "").lower(), notes=row.get("notes", "")))
    return links, errors
