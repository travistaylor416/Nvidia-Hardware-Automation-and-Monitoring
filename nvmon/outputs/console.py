"""Console output and saved JSON / text reports."""

import json
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..models import FAIL, PASS, WARN

COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", "INFO": "\033[36m"}
RESET = "\033[0m"
ALWAYS_SHOW_INFO = ("OS", "GPU driver", "OFED/DOCA")


def tag(status, color):
    text = f"[{status}]"
    return f"{COLORS.get(status, '')}{text}{RESET}" if color else text


def print_report(report, color=True, verbose=False):
    print(f"\n=== {report.name}  ({report.os} {report.role}, {report.address})  {tag(report.status, color)}")
    width = max((len(c.name) for c in report.checks), default=10)
    for check in report.checks:
        if check.status == "INFO" and not verbose and check.name not in ALWAYS_SHOW_INFO:
            continue
        print(f"  {tag(check.status, color):<6} {check.name:<{width}}  {check.detail}")
    for diag in report.port_diags:
        print(f"    - {diag.port:<10} oper={diag.state:<7} admin={diag.admin}")
        for hint in diag.hints:
            print(f"        * {hint}")


def print_summary(reports, color=True):
    counts = {PASS: 0, WARN: 0, FAIL: 0}
    for r in reports:
        counts[r.status] += 1
    print("\n" + "-" * 60)
    print(f"{len(reports)} device(s): " + "  ".join(f"{tag(k, color)} {v}" for k, v in counts.items()))
    for r in reports:
        if r.status != PASS:
            print(f"  {tag(r.status, color):<6} {r.name}: {', '.join(c.name for c in r.problems())}")


def print_samples(samples):
    print(f"\n{'Device':<14}{'Port':<14}{'Oper':<6}{'Media':<9}{'Rx dBm (min)':>13}{'Tx dBm (min)':>13}"
          f"{'Temp C':>8}{'CRC':>10}{'Symbol':>10}{'FEC unc':>10}{'Flaps':>7}")
    for smp in samples:
        def mn(q):
            v = smp.dom.get(q)
            return f"{min(v):.2f}" if v else "-"

        def c(key):
            v = smp.counters.get(key)
            return "-" if v is None else str(int(v))
        temp = smp.dom.get("temperature_c")
        print(f"{smp.device:<14}{smp.port:<14}{smp.oper:<6}{smp.media:<9}{mn('rx_power_dbm'):>13}{mn('tx_power_dbm'):>13}"
              f"{(f'{max(temp):.1f}' if temp else '-'):>8}{c('crc_errors'):>10}{c('symbol_errors'):>10}"
              f"{c('fec_uncorrectable'):>10}{c('link_downed'):>7}")


def print_links(results, color=True, verbose=False):
    if not results:
        print("\nNo links analysed (add cables to links.csv for end-to-end isolation).")
        return
    print(f"\n{'Status':<8}{'Link / port':<48}{'Suspected component':<22}Location")
    for lr in results:
        if lr.status == PASS and not verbose:
            continue
        print(f"{tag(lr.status, color):<8}{lr.link_id[:47]:<48}{lr.component:<22}{lr.location}")
        if not lr.evidence and lr.summary and lr.status != PASS:
            print(f"{'':<8}  - {lr.summary}")
        for ev in lr.evidence:
            print(f"{'':<8}  - {ev}")
        if lr.action and lr.status != PASS:
            print(f"{'':<8}  > {lr.action}")
    ok = sum(lr.status == PASS for lr in results)
    print(f"\n{len(results)} link(s)/port(s): {ok} ok, {len(results) - ok} need attention")


def _safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def save_run(report_dir, reports=(), samples=(), link_results=(), extra=None):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(report_dir) / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "devices": [asdict(r) | {"status": r.status} for r in reports],
        "ports": [asdict(s) for s in samples],
        "links": [asdict(lr) for lr in link_results],
        **(extra or {}),
    }
    (run_dir / "report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    for r in reports:
        if not r.port_diags:
            continue
        diag_dir = run_dir / "port-diag" / _safe(r.name)
        diag_dir.mkdir(parents=True, exist_ok=True)
        for d in r.port_diags:
            lines = [f"# {r.name} {d.port}  oper={d.state} admin={d.admin}", "", "Hints:"]
            lines += [f"  * {h}" for h in d.hints]
            for cmd, out in d.outputs.items():
                lines += ["", "=" * 70, f"$ {cmd}", "=" * 70, out]
            (diag_dir / f"{_safe(d.port)}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return run_dir
