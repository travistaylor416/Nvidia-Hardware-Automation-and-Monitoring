"""
Collect PortSamples over SSH.

Switches (NVOS / Cumulus): port state from `nv show interface`, then per-port counter and module
commands from settings.metrics.<os>_counter_commands / <os>_module_commands.

Servers (Ubuntu / DGX OS): every port that is cabled in links.csv, carries a fabric address, or
(optionally) every HCA port.  Ethernet-mode ports use ethtool -S / -m; InfiniBand-mode ports use
sysfs counters plus mlxlink for DOM/BER.
"""

import fnmatch

from ..checks.server import parse_ibdev2netdev, parse_ip_brief
from ..checks.switch import data_ports, get_ports
from ..models import PortSample
from ..ssh import open_session, safe_token
from .parse import canonicalize, ib_state, parse_ib_sysfs

SYSFS_CMD = ("grep -H . /sys/class/infiniband/*/ports/*/state /sys/class/infiniband/*/ports/*/phys_state "
             "/sys/class/infiniband/*/ports/*/rate /sys/class/infiniband/*/ports/*/link_layer "
             "/sys/class/infiniband/*/ports/*/counters/* 2>/dev/null")


def merge_bundle(sample, bundle):
    for attr in ("counters", "ber", "thresholds", "module"):
        target = getattr(sample, attr)
        for key, value in bundle[attr].items():
            target.setdefault(key, value)
    for q, values in bundle["dom"].items():
        sample.dom.setdefault(q, values)
    sample.alarms += [a for a in bundle["alarms"] if a not in sample.alarms]
    if sample.media in ("unknown", "") and bundle["media"] != "unknown":
        sample.media = bundle["media"]


def run_alternatives(sess, items, templates, batch):
    """items: [(sample, fields)].  For each sample, use the first template that succeeds."""
    results, last, pending = {}, {}, list(items)
    for template in templates:
        if not pending:
            break
        runnable, cmds, nxt = [], [], []
        for sample, fields in pending:
            try:
                cmds.append(template.format(**{k: safe_token(v) for k, v in fields.items() if v}))
                runnable.append((sample, fields))
            except (KeyError, ValueError):
                nxt.append((sample, fields))
        if cmds:
            for (sample, fields), res in zip(runnable, sess.run_many(cmds, batch=batch)):
                if res.ok and res.stdout.strip():
                    results[id(sample)] = res
                else:
                    last[id(sample)] = res
                    nxt.append((sample, fields))
        pending = nxt
    for sample, _ in pending:
        res = last.get(id(sample))
        if res:
            sample.errors.append(f"{res.command}: {res.text[:160]}")
    return results


def _apply(sess, items, templates, batch):
    found = run_alternatives(sess, items, templates, batch)
    for sample, _ in items:
        if id(sample) in found:
            merge_bundle(sample, canonicalize(found[id(sample)].stdout))


def collect_switch(device, links, s):
    with open_session(device, s) as sess:
        ports = data_ports(get_ports(sess), device, s)
        if s.metrics.switch_ports == "monitored":
            linked = {p.lower() for link in links for p in link.ports_for(device.name)}
            if linked or device.port_patterns:
                ports = [p for p in ports if p["name"].lower() in linked
                         or any(fnmatch.fnmatch(p["name"], pat) for pat in device.port_patterns)]
        samples = [PortSample(device.name, "switch", device.os, p["name"], oper=p["oper"],
                              admin=p["admin"], speed=p.get("speed", "")) for p in ports]
        items = [(smp, {"port": smp.port}) for smp in samples]
        batch = getattr(s.metrics, f"batch_{device.os}", False)
        _apply(sess, items, getattr(s.metrics, f"{device.os}_counter_commands"), batch)
        _apply(sess, items, getattr(s.metrics, f"{device.os}_module_commands"), batch)
    return samples


def collect_server(device, links, s):
    m = s.metrics
    with open_session(device, s) as sess:
        link_out, addr_out, rdma_out, sysfs_out = (r.stdout for r in sess.run_many(
            ["ip -br link show", "ip -br addr show", "ibdev2netdev", SYSFS_CMD], batch=m.batch_ubuntu))
        link_state = parse_ip_brief(link_out)
        addrs = parse_ip_brief(addr_out)
        sysfs = parse_ib_sysfs(sysfs_out)
        netdev_to_hca = {r["netdev"]: (r["hca"], r["port"]) for r in parse_ibdev2netdev(rdma_out)}
        hca_to_netdev = {v: k for k, v in netdev_to_hca.items()}

        wanted = [p for link in links for p in link.ports_for(device.name)]
        for fa in device.fabric_addresses:
            wanted += [ifname for ifname, info in addrs.items()
                       if any(a.split("/")[0] == fa.ip for a in info["addrs"])]
        if m.server_all_rdma_ports:
            wanted += [f"{hca}/{port}" for hca, port in sorted(sysfs)]

        samples, seen, eth_items, ib_items = [], set(), [], []
        for name in wanted:
            if "/" in name:
                hca, hca_port = name.split("/", 1)
                netdev = hca_to_netdev.get((hca, hca_port))
            else:
                netdev = name
                hca, hca_port = netdev_to_hca.get(name, (None, None))
            port_name = netdev or f"{hca}/{hca_port}"
            if port_name in seen:
                continue
            seen.add(port_name)
            aliases = [a for a in (netdev, f"{hca}/{hca_port}" if hca else None) if a and a != port_name]
            sample = PortSample(device.name, "server", device.os, port_name, aliases=aliases, admin="up")
            info = sysfs.get((hca, hca_port)) if hca else None
            if not info and not (netdev and netdev in link_state):
                continue  # port not on this host: its link reports "no metrics for end X"
            samples.append(sample)

            if info and info.get("link_layer", "").lower() == "infiniband":
                sample.oper = ib_state(info.get("state", ""), info.get("phys_state", ""))
                sample.speed = info.get("rate", "")
                merge_bundle(sample, canonicalize(info["counters_text"]))
                ib_items.append((sample, {"hca": hca, "hca_port": hca_port}))
            elif netdev and netdev in link_state:
                state = link_state[netdev]["state"]
                sample.oper = "up" if state == "UP" else "down" if "DOWN" in state else "unknown"
                eth_items.append((sample, {"port": netdev}))
            else:
                sample.oper = ib_state(info.get("state", ""), info.get("phys_state", ""))

        _apply(sess, eth_items, m.ubuntu_counter_commands, m.batch_ubuntu)
        _apply(sess, eth_items, m.ubuntu_module_commands, m.batch_ubuntu)
        _apply(sess, ib_items, m.ubuntu_ib_module_commands, m.batch_ubuntu)
    return samples


def collect_device(device, links, s):
    """Returns (samples, error_message_or_None)."""
    try:
        if device.is_switch:
            return collect_switch(device, links, s), None
        return collect_server(device, links, s), None
    except Exception as exc:  # noqa: BLE001 - reported as nvmon_up 0
        return [], f"{type(exc).__name__}: {exc}"
