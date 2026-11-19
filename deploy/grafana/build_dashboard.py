"""
Generate the nvmon Grafana dashboard JSON.

    python deploy/grafana/build_dashboard.py                    # prefix "nvmon" -> nvmon-dashboard.json
    python deploy/grafana/build_dashboard.py --prefix acme_nv   # if you changed prometheus.metric_prefix

Import in Grafana: Dashboards -> New -> Import -> upload the JSON -> pick your Prometheus datasource.
"""

import argparse
import json
from pathlib import Path

DS = {"type": "prometheus", "uid": "${datasource}"}


def target(expr, legend="", fmt="time_series", instant=False, ref="A"):
    return {"datasource": DS, "expr": expr, "legendFormat": legend, "format": fmt,
            "instant": instant, "range": not instant, "refId": ref}


def panel(pid, title, kind, grid, targets, unit="short", desc="", extra=None):
    p = {"id": pid, "title": title, "type": kind, "datasource": DS, "gridPos": grid, "targets": targets,
         "description": desc, "fieldConfig": {"defaults": {"unit": unit}, "overrides": []}, "options": {}}
    p.update(extra or {})
    return p


def build(prefix):
    sel = 'device=~"$device"'
    psel = 'device=~"$device",port=~"$port"'
    P = prefix
    thresholds_status = {"mode": "absolute", "steps": [{"color": "green", "value": None},
                                                       {"color": "orange", "value": 1}, {"color": "red", "value": 2}]}
    panels = [
        panel(1, "Devices reachable", "stat", {"x": 0, "y": 0, "w": 4, "h": 4},
              [target(f"sum({P}_up{{{sel}}}) / count({P}_up{{{sel}}})", instant=True)], unit="percentunit"),
        panel(2, "Links at fault", "stat", {"x": 4, "y": 0, "w": 4, "h": 4},
              [target(f"count({P}_link_status == 2) or vector(0)", instant=True)],
              extra={"fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
                  {"color": "green", "value": None}, {"color": "red", "value": 1}]}}, "overrides": []}}),
        panel(3, "Links warning", "stat", {"x": 8, "y": 0, "w": 4, "h": 4},
              [target(f"count({P}_link_status == 1) or vector(0)", instant=True)],
              extra={"fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
                  {"color": "green", "value": None}, {"color": "orange", "value": 1}]}}, "overrides": []}}),
        panel(4, "Failing health checks", "stat", {"x": 12, "y": 0, "w": 4, "h": 4},
              [target(f"count({P}_check_status{{{sel}}} == 2) or vector(0)", instant=True)]),
        panel(5, "Ports down (admin up)", "stat", {"x": 16, "y": 0, "w": 4, "h": 4},
              [target(f"count(({P}_port_oper_up{{{sel}}} < 1) and on(device,port) ({P}_port_admin_up == 1)) or vector(0)",
                      instant=True)]),
        panel(6, "Collection time", "stat", {"x": 20, "y": 0, "w": 4, "h": 4},
              [target(f"max({P}_collect_duration_seconds{{{sel}}})", instant=True)], unit="s"),

        panel(10, "Fault isolation - where is the link failing?", "table", {"x": 0, "y": 4, "w": 24, "h": 8},
              [target(f"{P}_link_fault_info", fmt="table", instant=True)],
              desc="One row per unhealthy link. 'component' is nvmon's verdict: switch_port, switch_transceiver, "
                   "node_port, node_transceiver, cable, cable_or_far_end, subnet_manager or ambiguous.",
              extra={"transformations": [{"id": "organize", "options": {
                  "excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True, "mapped": True},
                  "renameByName": {"Value": "status (1 warn / 2 fault)"}}}],
                  "fieldConfig": {"defaults": {"thresholds": thresholds_status}, "overrides": []}}),

        panel(20, "Rx errors / s (CRC + symbol + FEC uncorrectable)", "timeseries", {"x": 0, "y": 12, "w": 12, "h": 8},
              [target(f"rate({P}_port_crc_errors_total{{{psel}}}[5m])", "{{device}} {{port}} crc", ref="A"),
               target(f"rate({P}_port_symbol_errors_total{{{psel}}}[5m])", "{{device}} {{port}} symbol", ref="B"),
               target(f"rate({P}_port_fec_uncorrectable_total{{{psel}}}[5m])", "{{device}} {{port}} fec-unc", ref="C")],
              unit="ops"),
        panel(21, "Link flaps (last 1h)", "timeseries", {"x": 12, "y": 12, "w": 12, "h": 8},
              [target(f"increase({P}_port_link_downed_total{{{psel}}}[1h]) > 0", "{{device}} {{port}}")]),

        panel(30, "Rx optical power per lane", "timeseries", {"x": 0, "y": 20, "w": 12, "h": 8},
              [target(f"{P}_port_rx_power_dbm{{{psel}}}", "{{device}} {{port}} L{{lane}}")], unit="dBm",
              desc="Low Rx with normal far-end Tx = loss in fiber/connectors."),
        panel(31, "Tx optical power per lane", "timeseries", {"x": 12, "y": 20, "w": 12, "h": 8},
              [target(f"{P}_port_tx_power_dbm{{{psel}}}", "{{device}} {{port}} L{{lane}}")], unit="dBm",
              desc="Low Tx = that transceiver's laser is failing."),
        panel(32, "Transceiver temperature", "timeseries", {"x": 0, "y": 28, "w": 12, "h": 8},
              [target(f"{P}_port_module_temperature_celsius{{{psel}}}", "{{device}} {{port}}")], unit="celsius"),
        panel(33, "Bit error ratio", "timeseries", {"x": 12, "y": 28, "w": 12, "h": 8},
              [target(f"{P}_port_effective_ber{{{psel}}}", "{{device}} {{port}} effective", ref="A"),
               target(f"{P}_port_raw_ber{{{psel}}}", "{{device}} {{port}} raw", ref="B")],
              unit="sci", extra={"fieldConfig": {"defaults": {"unit": "sci", "custom": {
                  "scaleDistribution": {"type": "log", "log": 10}}}, "overrides": []}}),

        panel(40, "Port state", "state-timeline", {"x": 0, "y": 36, "w": 24, "h": 10},
              [target(f"{P}_port_oper_up{{{psel}}}", "{{device}} {{port}}")],
              extra={"fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
                  {"color": "red", "value": None}, {"color": "orange", "value": 0.5}, {"color": "green", "value": 1}]},
                  "mappings": [{"type": "value", "options": {"0": {"text": "down"}, "0.5": {"text": "init"},
                                                             "1": {"text": "up"}}}]}, "overrides": []}}),
        panel(50, "Health checks not passing", "table", {"x": 0, "y": 46, "w": 24, "h": 8},
              [target(f"{P}_check_status{{{sel}}} > 0", fmt="table", instant=True)],
              extra={"transformations": [{"id": "organize", "options": {
                  "excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True},
                  "renameByName": {"Value": "status (1 warn / 2 fail)"}}}]}),
        panel(51, "Transceivers", "table", {"x": 0, "y": 54, "w": 24, "h": 8},
              [target(f"{P}_port_module_info{{{psel}}}", fmt="table", instant=True)],
              extra={"transformations": [{"id": "organize", "options": {
                  "excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True, "Value": True}}}]}),
    ]
    return {
        "__inputs": [{"name": "DS_PROMETHEUS", "label": "Prometheus", "type": "datasource", "pluginId": "prometheus"}],
        "title": "nvmon - NVIDIA fabric ports & fault isolation",
        "uid": "nvmon-fabric",
        "tags": ["nvmon", "nvidia", "infiniband", "network"],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "1m",
        "time": {"from": "now-6h", "to": "now"},
        "templating": {"list": [
            {"name": "datasource", "type": "datasource", "query": "prometheus", "label": "Datasource"},
            {"name": "device", "type": "query", "datasource": DS, "label": "Device", "includeAll": True,
             "multi": True, "refresh": 2, "query": {"query": f"label_values({P}_up, device)", "refId": "dev"},
             "current": {"text": "All", "value": "$__all"}},
            {"name": "port", "type": "query", "datasource": DS, "label": "Port", "includeAll": True,
             "multi": True, "refresh": 2,
             "query": {"query": f'label_values({P}_port_oper_up{{device=~"$device"}}, port)', "refId": "port"},
             "current": {"text": "All", "value": "$__all"}},
        ]},
        "panels": panels,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="nvmon")
    ap.add_argument("--out", default=str(Path(__file__).with_name("nvmon-dashboard.json")))
    args = ap.parse_args()
    Path(args.out).write_text(json.dumps(build(args.prefix), indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
