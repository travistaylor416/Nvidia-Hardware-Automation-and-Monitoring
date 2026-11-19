"""
nvmon - NVIDIA server & switch health checks, port telemetry and link fault isolation.

Commands
    check      health checks (DNS, BMC, OS, fabric IPs on servers; port state + diag on switches)
    metrics    one-shot port telemetry + fault isolation (use --interval N for counter deltas)
    exporter   long-running Prometheus exporter (http / textfile / pushgateway) + optional Jira
    list       show parsed inventory and links
    config     print the effective configuration (no secrets) - useful for security review
    jira-test  verify Jira URL + credentials (GET /myself)

Examples
    python -m nvmon check --only servers
    python -m nvmon check --device ib-leaf01 --ports "sw1p*" --jira
    python -m nvmon metrics --interval 30
    python -m nvmon metrics --prom-out nvmon.prom
    python -m nvmon exporter --jira
    python -m nvmon -c nvmon.toml config

Exit code (check/metrics): 0 all pass, 1 warnings, 2 failures, 3 usage/config error.
"""

import argparse
import getpass
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__, ssh
from . import settings as settings_mod
from .inventory import load_inventory, load_links
from .models import FAIL, WARN


def build_parser():
    p = argparse.ArgumentParser(prog="nvmon", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", help="TOML config (default: $NVMON_CONFIG or ./nvmon.toml)")
    p.add_argument("--version", action="version", version=f"nvmon {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-i", "--inventory", help="inventory CSV (overrides general.inventory)")
    common.add_argument("--links", help="links CSV (overrides general.links)")
    common.add_argument("--only", choices=("all", "servers", "switches"), default="all")
    common.add_argument("--device", nargs="+", metavar="NAME", help="only these device names")
    common.add_argument("--workers", type=int, help="devices processed in parallel")
    common.add_argument("--ask-pass", action="store_true", help="prompt once for the SSH password")
    common.add_argument("--no-color", action="store_true")
    common.add_argument("-v", "--verbose", action="store_true", help="show INFO/PASS rows")
    common.add_argument("--debug", action="store_true", help="log every SSH command")

    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", parents=[common], help="health checks")
    c.add_argument("--ports", nargs="+", metavar="GLOB", help="switch ports to monitor (overrides CSV Ports)")
    c.add_argument("--include-admin-down", action="store_true")
    c.add_argument("--max-diag", type=int, help="max ports diagnosed per switch")
    c.add_argument("--no-save", action="store_true", help="don't write reports/<timestamp>/")
    c.add_argument("--jira", action="store_true", help="raise/update Jira tickets for findings")
    c.add_argument("--jira-dry-run", action="store_true", help="show Jira payloads without sending")
    c.add_argument("--prom-out", metavar="FILE", help="also write check results as Prometheus text")

    m = sub.add_parser("metrics", parents=[common], help="port telemetry + fault isolation")
    m.add_argument("--interval", type=int, help="take two samples N seconds apart for counter deltas")
    m.add_argument("--no-save", action="store_true")
    m.add_argument("--prom-out", metavar="FILE", help="write Prometheus text to FILE ('-' = stdout)")
    m.add_argument("--push", action="store_true", help="push to the configured Pushgateway")
    m.add_argument("--jira", action="store_true")
    m.add_argument("--jira-dry-run", action="store_true")

    e = sub.add_parser("exporter", parents=[common], help="run the Prometheus exporter")
    e.add_argument("--once", action="store_true", help="single cycle, deliver textfile/push, then exit")
    e.add_argument("--listen", metavar="ADDR:PORT", help="override prometheus.listen_address/port")
    e.add_argument("--jira", action="store_true", help="raise/update Jira tickets each cycle")

    sub.add_parser("list", parents=[common], help="show inventory + links")
    sub.add_parser("config", help="print effective configuration (secrets redacted)")
    sub.add_parser("jira-test", help="verify Jira connectivity and credentials")
    return p


def select_devices(devices, args):
    if args.only == "servers":
        devices = [d for d in devices if d.is_server]
    elif args.only == "switches":
        devices = [d for d in devices if d.is_switch]
    if args.device:
        wanted = {n.lower() for n in args.device}
        devices = [d for d in devices if d.name.lower() in wanted]
    return devices


def load_scope(args, s):
    devices, errors = load_inventory(args.inventory or s.general.inventory, s)
    links, link_errors = load_links(args.links or s.general.links)
    for err in errors + link_errors:
        print(f"skipped {err}")
    return select_devices(devices, args), links


def exit_code(statuses):
    statuses = set(statuses)
    return 2 if FAIL in statuses else 1 if WARN in statuses else 0


def do_jira(args, s, reports=(), link_results=()):
    from .outputs.jira import findings_from, raise_tickets
    for line in raise_tickets(findings_from(reports, link_results), s, force_dry_run=getattr(args, "jira_dry_run", False)):
        print(line)


# --------------------------------------------------------------------------- commands


def cmd_check(args, s, devices, links, color):
    from .checks import run_device_checks
    from .outputs import console, prometheus

    print(f"nvmon {__version__}: checking {len(devices)} device(s) with {s.general.workers} worker(s)...")
    order = {d.name: i for i, d in enumerate(devices)}
    reports = []
    with ThreadPoolExecutor(max_workers=max(1, s.general.workers)) as pool:
        futures = [pool.submit(run_device_checks, d, s, args.include_admin_down, args.max_diag, args.ports) for d in devices]
        for fut in as_completed(futures):
            rep = fut.result()
            print(f"  done: {rep.name} -> {rep.status}", flush=True)
            reports.append(rep)
    reports.sort(key=lambda r: order[r.name])
    for rep in reports:
        console.print_report(rep, color=color, verbose=args.verbose)
    console.print_summary(reports, color=color)

    if not args.no_save:
        print(f"\nReport saved to {console.save_run(s.general.report_dir, reports=reports)}")
    if args.prom_out:
        _write_prom(prometheus.build(reports=reports), args.prom_out)
    if args.jira or args.jira_dry_run:
        do_jira(args, s, reports=reports)
    return exit_code(r.status for r in reports)


def _collect_all(devices, links, s):
    from .metrics.collect import collect_device
    samples, status = [], {}

    def one(d):
        t0 = time.time()
        got, err = collect_device(d, links, s)
        return d, got, err, time.time() - t0

    with ThreadPoolExecutor(max_workers=max(1, s.general.workers)) as pool:
        for d, got, err, dur in pool.map(one, devices):
            samples += got
            status[d.name] = {"role": d.role, "os": d.os, "up": err is None, "duration": round(dur, 3),
                              "timestamp": time.time(), "error": err}
            print(f"  {d.name}: {'%d port(s)' % len(got) if err is None else 'FAILED ' + err}", flush=True)
    return samples, status


def _write_prom(text, dest):
    if dest == "-":
        sys.stdout.write(text)
    else:
        from .outputs.prometheus import write_textfile
        print(f"Prometheus text written to {write_textfile(text, dest)}")


def cmd_metrics(args, s, devices, links, color):
    from .metrics.isolate import analyze
    from .outputs import console, prometheus

    interval = args.interval if args.interval is not None else s.metrics.sample_interval
    print(f"nvmon {__version__}: collecting port metrics from {len(devices)} device(s)...")
    previous = None
    if interval and interval > 0:
        first, _ = _collect_all(devices, links, s)
        previous = {(x.device, x.port): x for x in first}
        print(f"waiting {interval}s for second sample (counter deltas)...")
        time.sleep(interval)
    samples, status = _collect_all(devices, links, s)
    results = analyze(samples, links, s.thresholds, previous=previous)

    if args.verbose:
        console.print_samples(samples)
    console.print_links(results, color=color, verbose=args.verbose)
    for name, st in status.items():
        if not st["up"]:
            print(f"  {console.tag(FAIL, color)} {name}: {st['error']}")

    if not args.no_save:
        print(f"\nReport saved to {console.save_run(s.general.report_dir, samples=samples, link_results=results)}")
    text = prometheus.build(samples, results, status)
    if args.prom_out:
        _write_prom(text, args.prom_out)
    if args.push:
        for line in prometheus.deliver(text, s, outputs=["pushgateway"]):
            print(line)
    if args.jira or args.jira_dry_run:
        do_jira(args, s, link_results=results)
    statuses = [lr.status for lr in results] + [FAIL for st in status.values() if not st["up"]]
    return exit_code(statuses)


def cmd_exporter(args, s, devices, links, color):
    from .outputs import exporter
    if args.listen:
        addr, _, port = args.listen.rpartition(":")
        s.prometheus.listen_address, s.prometheus.listen_port = addr or s.prometheus.listen_address, int(port)
    jira_cb = None
    if args.jira:
        from .outputs.jira import findings_from, raise_tickets

        def jira_cb(reports, results):
            for line in raise_tickets(findings_from(reports, results), s):
                logging.getLogger("nvmon.jira").info(line)
    state = exporter.serve(devices, links, s, jira_cb=jira_cb, once=args.once)
    if args.once and state:
        print(f"one cycle complete ({len(state.text.splitlines())} metric lines)")
    return 0


def cmd_list(args, s, devices, links, color):
    print(f"{'Name':<16}{'Role':<8}{'OS':<9}{'Mgmt':<17}{'BMC':<17}Fabric / Ports")
    for d in devices:
        extra = ";".join(map(str, d.fabric_addresses)) if d.is_server else ";".join(d.port_patterns) or "(all)"
        print(f"{d.name:<16}{d.role:<8}{d.os:<9}{d.mgmt_address:<17}{d.bmc_address or '-':<17}{extra}")
    print(f"\n{len(links)} link(s) in {args.links or s.general.links}")
    for link in links:
        print(f"  {link.link_id}  {link.media or ''}")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "debug", False) else logging.INFO
                        if args.command == "exporter" else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        s = settings_mod.set_current(settings_mod.load(args.config))
    except (OSError, ValueError) as exc:
        print(f"config error: {exc}")
        return 3

    if args.command == "config":
        print(json.dumps(s.to_dict(), indent=2))
        return 0
    if args.command == "jira-test":
        from .outputs.jira import JiraClient, JiraError
        try:
            me = JiraClient(s.jira, settings_mod.secret("jira_user"), settings_mod.secret("jira_token")).whoami()
            print(f"Jira OK: authenticated as {me.get('displayName') or me.get('name')} at {s.jira.url}")
            return 0
        except JiraError as exc:
            print(f"Jira FAILED: {exc}")
            return 2

    if args.workers:
        s.general.workers = args.workers
    color = not args.no_color and sys.stdout.isatty()
    try:
        devices, links = load_scope(args, s)
    except FileNotFoundError as exc:
        print(exc)
        return 3
    if not devices:
        print("No matching devices.")
        return 3
    if args.ask_pass:
        ssh.PROMPTED_PASSWORD = getpass.getpass("SSH password: ")

    handler = {"check": cmd_check, "metrics": cmd_metrics, "exporter": cmd_exporter, "list": cmd_list}[args.command]
    return handler(args, s, devices, links, color)


if __name__ == "__main__":
    sys.exit(main())
