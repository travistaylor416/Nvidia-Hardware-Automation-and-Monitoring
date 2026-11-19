"""
Ubuntu / DGX OS server checks:

    Reachability  ping mgmt IP from the monitoring host
    OS            /etc/os-release, kernel, uptime, GPU driver, DOCA/OFED (info)
    DNS           configured resolvers vs expected, host resolves itself + test names,
                  forward/reverse records seen from the monitoring host
    BMC           BMC reachable (ping + Redfish 443), in-band `ipmitool lan print` matches inventory
    Fabric        every expected fabric IP is assigned, on the right interface, link UP, MTU/speed
"""

import ipaddress
import re
import shlex

from .. import netutil
from ..models import FAIL, INFO, PASS, WARN, DeviceReport, guarded
from ..ssh import open_session

# ------------------------------------------------------------------ parsers (pure, unit tested)


def _clean_ip(token):
    token = token.split("#", 1)[0].split("%", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def parse_resolv_conf(text):
    servers = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            ip = _clean_ip(parts[1])
            if ip and ip not in servers:
                servers.append(ip)
    return servers


_KEY_LINE = re.compile(r"^\s*[A-Za-z][A-Za-z ]+:\s")


def parse_resolvectl(text):
    """Handles `resolvectl dns` (Global:/Link N (ifname): ...) and `resolvectl status` blocks."""
    servers, in_block = [], False
    for line in text.splitlines():
        stripped = line.strip()
        values = None
        m = re.match(r"^(Global|Link \d+ \([^)]*\)):\s*(.*)$", stripped)
        if m:
            values, in_block = m.group(2), False
        elif stripped.startswith(("DNS Servers:", "Current DNS Server:")):
            values, in_block = stripped.split(":", 1)[1], stripped.startswith("DNS Servers:")
        elif in_block and stripped and not _KEY_LINE.match(line):
            values = stripped
        else:
            in_block = False
        for token in (values or "").split():
            ip = _clean_ip(token)
            if ip and ip not in servers:
                servers.append(ip)
    return servers


def parse_ipmitool_lan(text):
    fields = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key and key not in fields:
            fields[key] = value.strip()
    return {
        "ip": fields.get("IP Address", ""),
        "source": fields.get("IP Address Source", ""),
        "mask": fields.get("Subnet Mask", ""),
        "mac": fields.get("MAC Address", ""),
        "gateway": fields.get("Default Gateway IP", ""),
        "vlan": fields.get("802.1q VLAN ID", ""),
    }


def parse_ip_brief(text):
    """`ip -br addr show` / `ip -br link show` -> {ifname: {"state": "UP", "addrs": [...]}}"""
    interfaces = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        interfaces[parts[0].split("@", 1)[0]] = {"state": parts[1].upper(), "addrs": parts[2:]}
    return interfaces


def parse_os_release(text):
    data = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip().strip('"')
    return data


def parse_ibdev2netdev(text):
    """'mlx5_0 port 1 ==> ibp12s0 (Up)' -> [{"hca", "port", "netdev", "state"}]"""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+port\s+(\d+)\s+==>\s+(\S+)\s+\((\w+)\)", line.strip())
        if m:
            rows.append(dict(zip(("hca", "port", "netdev", "state"), m.groups())))
    return rows


def compare_dns(found, expected):
    if not expected:
        return INFO, f"resolvers {found or 'none'} (no expected list configured)"
    if not found:
        return FAIL, "no resolvers configured"
    missing = [s for s in expected if s not in found]
    extra = [s for s in found if s not in expected and not s.startswith("127.")]
    if not missing and not extra:
        return PASS, f"resolvers {found}"
    if len(missing) == len(expected):
        return FAIL, f"resolvers {found}, expected {expected}"
    parts = ([f"missing {missing}"] if missing else []) + ([f"unexpected {extra}"] if extra else [])
    return WARN, f"resolvers {found}: " + ", ".join(parts)


# ------------------------------------------------------------------ external checks (monitoring host)


def check_reachability(device, report):
    ok = netutil.ping(device.mgmt_address)
    report.add("Mgmt ping", PASS if ok else FAIL,
               f"{device.mgmt_address} {'reachable' if ok else 'no reply (ICMP blocked or host down)'}")


def check_dns_records(device, report):
    ips = netutil.forward_lookup(device.hostname)
    if not ips:
        report.add("DNS A record", WARN, f"{device.hostname} does not resolve from monitoring host")
    elif device.mgmt_address in ips:
        report.add("DNS A record", PASS, f"{device.hostname} -> {', '.join(ips)}")
    else:
        report.add("DNS A record", FAIL, f"{device.hostname} -> {', '.join(ips)}, inventory says {device.mgmt_address}")

    if _clean_ip(device.mgmt_address):
        ptr = netutil.reverse_lookup(device.mgmt_address)
        short = device.hostname.split(".")[0].lower()
        if not ptr:
            report.add("DNS PTR record", WARN, f"no PTR for {device.mgmt_address}")
        elif ptr.lower().split(".")[0] == short:
            report.add("DNS PTR record", PASS, f"{device.mgmt_address} -> {ptr}")
        else:
            report.add("DNS PTR record", WARN, f"{device.mgmt_address} -> {ptr} (expected {device.hostname})")


def check_bmc_external(device, report, s):
    if not device.bmc_address:
        report.add("BMC reachability", INFO, "no BMC Address in inventory")
        return
    pings = netutil.ping(device.bmc_address)
    open_ports = [p for p in s.checks.bmc_tcp_ports if netutil.tcp_open(device.bmc_address, p)]
    if pings or open_ports:
        report.add("BMC reachability", PASS,
                   f"{device.bmc_address} ping={'ok' if pings else 'no'} tcp={open_ports or 'none'}")
    else:
        report.add("BMC reachability", FAIL,
                   f"{device.bmc_address} no ping and ports {s.checks.bmc_tcp_ports} closed")


# ------------------------------------------------------------------ in-band checks (over SSH)


def check_os(sess, device, report):
    osr = parse_os_release(sess.run("cat /etc/os-release").stdout)
    kernel = sess.run("uname -r").stdout
    uptime = sess.run("uptime -p").stdout
    pretty = osr.get("PRETTY_NAME", "unknown")
    detail = f"{pretty}, kernel {kernel}, {uptime}"

    status = PASS
    if osr.get("ID", "").lower() != "ubuntu" and "ubuntu" not in osr.get("ID_LIKE", "").lower():
        status, detail = WARN, detail + " (not Ubuntu-based)"
    want = device.expected_os_version
    if want and want not in pretty and want != osr.get("VERSION_ID"):
        status, detail = FAIL, detail + f" (expected '{want}')"
    report.add("OS", status, detail, os_release=osr, kernel=kernel)

    gpu = sess.run("command -v nvidia-smi >/dev/null && nvidia-smi --query-gpu=name,driver_version --format=csv,noheader")
    if gpu.ok and gpu.stdout:
        lines = gpu.stdout.splitlines()
        report.add("GPU driver", INFO, f"{len(lines)} GPU(s): {lines[0]}", gpus=lines)
    stack = sess.run("(command -v ofed_info >/dev/null && ofed_info -s) || "
                     "(dpkg-query -W -f='${Version}' doca-ofed 2>/dev/null)")
    if stack.ok and stack.stdout:
        report.add("OFED/DOCA", INFO, stack.stdout.splitlines()[0].rstrip(":"))


def check_dns_inband(sess, device, report, s):
    servers = parse_resolv_conf(sess.run("cat /etc/resolv.conf").stdout)
    if not servers or any(x.startswith("127.0.0.53") for x in servers):
        upstream = parse_resolvectl(sess.run("resolvectl dns 2>/dev/null || resolvectl status 2>/dev/null "
                                             "|| systemd-resolve --status 2>/dev/null").stdout)
        if upstream:
            servers = upstream
    status, detail = compare_dns(servers, s.checks.expected_dns_servers)
    report.add("DNS resolvers", status, detail, servers=servers)

    fqdn = sess.run("hostname -f 2>/dev/null || hostname").stdout or device.hostname
    got = sess.run(f"getent ahostsv4 {shlex.quote(fqdn)} | awk '{{print $1}}' | sort -u").stdout.split()
    if not got:
        report.add("DNS self lookup", FAIL, f"{fqdn} does not resolve on the host")
    elif device.mgmt_address in got:
        report.add("DNS self lookup", PASS, f"{fqdn} -> {', '.join(got)}")
    elif all(ip.startswith("127.") for ip in got):
        report.add("DNS self lookup", WARN, f"{fqdn} -> {', '.join(got)} (from /etc/hosts, not DNS)")
    else:
        report.add("DNS self lookup", WARN, f"{fqdn} -> {', '.join(got)}, mgmt is {device.mgmt_address}")

    for name in s.checks.dns_test_names:
        ips = sess.run(f"getent ahostsv4 {shlex.quote(name)} | awk '{{print $1}}' | sort -u").stdout.split()
        report.add(f"DNS lookup {name}", PASS if ips else FAIL, ", ".join(ips) or "no answer")


def check_bmc_inband(sess, device, report, s):
    if not sess.run("command -v ipmitool").ok:
        report.add("BMC config", WARN, "ipmitool not installed (apt install ipmitool) - cannot read BMC LAN config")
        return
    res = sess.sudo(f"ipmitool lan print {int(s.checks.bmc_lan_channel)}")
    if not res.ok:
        report.add("BMC config", WARN, f"ipmitool failed (needs sudo / ipmi_devintf): {res.text[:200]}")
        return
    lan = parse_ipmitool_lan(res.stdout)
    detail = f"ip={lan['ip']} src={lan['source']} gw={lan['gateway']} mac={lan['mac']}"
    if not lan["ip"] or lan["ip"] == "0.0.0.0":
        report.add("BMC config", FAIL, "BMC has no IP address. " + detail, **lan)
    elif device.bmc_address and lan["ip"] != device.bmc_address:
        report.add("BMC config", FAIL, f"BMC IP {lan['ip']} != inventory {device.bmc_address}. " + detail, **lan)
    else:
        report.add("BMC config", PASS, detail, **lan)


def check_fabric(sess, device, report, s):
    if not device.fabric_addresses:
        report.add("Fabric", INFO, "no Fabric Addresses in inventory")
        return
    interfaces = parse_ip_brief(sess.run("ip -br addr show").stdout)
    rdma = parse_ibdev2netdev(sess.run("command -v ibdev2netdev >/dev/null && ibdev2netdev").stdout)
    hca_for = {row["netdev"]: f"{row['hca']}/{row['port']}" for row in rdma}
    want_mtu = s.checks.fabric_expected_mtu

    for want in device.fabric_addresses:
        name = f"Fabric {want.ip}"
        owner, assigned = None, None
        for ifname, info in interfaces.items():
            for addr in info["addrs"]:
                if addr.split("/")[0] == want.ip:
                    owner, assigned = ifname, addr
        if not owner:
            report.add(name, FAIL, f"{want} not assigned to any interface")
            continue

        state = interfaces[owner]["state"]
        sysfs = sess.run(f"cat /sys/class/net/{owner}/speed /sys/class/net/{owner}/mtu 2>/dev/null").stdout.split()
        speed = f"{int(sysfs[0]) // 1000}G" if sysfs and sysfs[0].isdigit() and int(sysfs[0]) > 0 else "?"
        mtu = int(sysfs[1]) if len(sysfs) > 1 and sysfs[1].isdigit() else None
        detail = f"{assigned} on {owner} [{state}] speed={speed} mtu={mtu}"
        if owner in hca_for:
            detail += f" hca={hca_for[owner]}"

        problems = []
        if state in ("DOWN", "LOWERLAYERDOWN"):
            problems.append((FAIL, "link down"))
        elif state != "UP":
            problems.append((WARN, f"state {state}"))
        if want.interface and want.interface != owner:
            problems.append((WARN, f"expected on {want.interface}"))
        if want.prefix is not None and "/" in assigned and int(assigned.split("/")[1]) != want.prefix:
            problems.append((WARN, f"prefix /{assigned.split('/')[1]} expected /{want.prefix}"))
        if want_mtu and mtu and mtu != want_mtu:
            problems.append((WARN, f"MTU {mtu} expected {want_mtu}"))

        status = PASS
        if problems:
            status = FAIL if any(st == FAIL for st, _ in problems) else WARN
            detail += " - " + "; ".join(msg for _, msg in problems)
        report.add(name, status, detail, interface=owner, state=state, speed=speed, mtu=mtu)

    if rdma:
        down = [r for r in rdma if r["state"].lower() != "up"]
        report.add("RDMA ports", WARN if down else INFO,
                   ", ".join(f"{r['hca']}/{r['port']}={r['netdev']}({r['state']})" for r in rdma), ports=rdma)


def run_server_checks(device, s):
    report = DeviceReport.for_device(device)
    guarded(report, "Mgmt ping", check_reachability, device, report)
    guarded(report, "DNS records", check_dns_records, device, report)
    guarded(report, "BMC reachability", check_bmc_external, device, report, s)
    try:
        with open_session(device, s) as sess:
            report.add("SSH", PASS, f"{device.username}@{device.mgmt_address}")
            guarded(report, "OS", check_os, sess, device, report)
            guarded(report, "DNS resolvers", check_dns_inband, sess, device, report, s)
            guarded(report, "BMC config", check_bmc_inband, sess, device, report, s)
            guarded(report, "Fabric", check_fabric, sess, device, report, s)
    except Exception as exc:  # noqa: BLE001
        report.add("SSH", FAIL, f"{device.username}@{device.mgmt_address}: {type(exc).__name__}: {exc}")
    return report
