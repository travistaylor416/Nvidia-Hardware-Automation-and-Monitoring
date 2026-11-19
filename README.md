# nvmon: NVIDIA fabric health, telemetry and fault isolation (v2.0.0)

nvmon checks NVIDIA servers and switches over SSH and reports the results three ways:

- **Health checks:** DNS, BMC, OS and fabric IPs on servers; port state plus diagnostics on switches.
- **Port telemetry for Prometheus/Grafana:** error counters, BER and transceiver light levels from **both ends of every cable**.
- **Link fault isolation:** a verdict on whether the **switch port, a transceiver, or the fiber/copper itself** is failing.
- **Jira tickets** for anything that fails, with de-duplication.

| OS | Device | Health checks | Port telemetry |
|---|---|---|---|
| **Ubuntu / DGX OS** | DGX/HGX servers | OS, DNS, BMC, fabric IPs | ConnectX ports: `ethtool -S/-m` (Ethernet), sysfs + `mlxlink` (InfiniBand) |
| **NVOS** | Quantum IB switches | OS version, `nv show interface`, diag on down ports | `nv show interface <p> counters/transceiver` |
| **Cumulus Linux** | Spectrum Ethernet switches | OS version, `nv show interface`, diag on down ports | `ethtool -S/-m`, `l1-show` |

Every endpoint, threshold, command and credential is a setting, so you can publish the repo on GitHub and drop it into a
corporate workflow by editing config only. See [SECURITY.md](SECURITY.md) for the security review.

## Layout

```
nvmon/
  settings.py        config loader: defaults < nvmon.toml < NVMON_* env vars < CLI flags; secrets env-only
  inventory.py       inventory.csv (devices) + links.csv (cable map)
  ssh.py             paramiko session, sudo, batched commands, command-injection guard
  checks/            point-in-time health checks
    server.py        Ubuntu: OS, DNS, BMC, fabric addresses
    switch.py        NVOS/Cumulus: nv show interface, per-port diag + hints
  metrics/           port telemetry
    collect.py       pulls counters + DOM from switch ports and server NIC/HCA ports
    parse.py         one canonicalizer for nv JSON, ethtool -S/-m, mlxlink, IB sysfs
    isolate.py       correlates both cable ends -> port vs transceiver vs fiber/copper
  outputs/
    console.py       terminal tables + reports/<timestamp>/report.json
    prometheus.py    exposition format, textfile, Pushgateway (stdlib only)
    exporter.py      long-running /metrics endpoint (+ optional bearer token)
    jira.py          Jira Cloud / Server-DC tickets with de-dupe (stdlib only)
  cli.py             `python -m nvmon <command>`
deploy/
  grafana/           dashboard JSON + generator (custom metric prefix)
  prometheus/        scrape config + alert rules
  systemd/           hardened service unit for the exporter
```

## Setup

```bash
python -m pip install -r requirements.txt
```

```bash
copy nvmon.example.toml nvmon.toml
```

```bash
copy inventory.example.csv inventory.csv
```

```bash
copy links.example.csv links.csv
```

Edit the three files. Then provide secrets as environment variables (see [.env.example](.env.example)), SSH keys, or `--ask-pass`.
`nvmon.toml`, `inventory.csv`, `links.csv` and `.env` are git-ignored.

**Config precedence:** built-in defaults, then `nvmon.toml` (or `--config` / `$NVMON_CONFIG`), then `NVMON_<SECTION>_<KEY>`
environment variables, then CLI flags. For example, `NVMON_JIRA_PROJECT_KEY=NET` or `NVMON_PROMETHEUS_LISTEN_PORT=9100`.
Run `python -m nvmon config` to print the effective settings. Secrets show only as present or absent.

## Commands

```bash
python -m nvmon list
```

```bash
python -m nvmon check --only servers
```

```bash
python -m nvmon check --device ib-leaf01 --ports "sw1p*" --jira-dry-run
```

```bash
python -m nvmon metrics --interval 30 -v
```

```bash
python -m nvmon exporter
```

```bash
python -m nvmon exporter --once
```

```bash
python -m nvmon jira-test
```

- `check`: health checks. Exit code 0/1/2 for pass/warn/fail, so you can run it from cron or CI.
- `metrics`: one-shot telemetry plus fault isolation. `--interval N` takes two samples so errors are judged on **new** counts.
- `exporter`: collects every `prometheus.interval` seconds and serves `/metrics`, writes a textfile, and/or pushes to a
  Pushgateway, depending on `prometheus.outputs`. Add `--jira` to raise tickets each cycle.

## Fault isolation: how nvmon decides where a link is failing

List each cable in `links.csv` (`A Device, A Port, B Device, B Port, Media`). Server ports can be a netdev (`ens1f0np0`) or an
HCA port (`mlx5_0/1`). For each cable, nvmon compares the two ends:

| Evidence | Verdict |
|---|---|
| No module/cable detected at one end | that end's **transceiver** |
| Tx power low at X | **transceiver at X** (laser failing) |
| Rx power low at Y while X transmits normally | **fiber/connectors** between them |
| Module over temperature | that **transceiver** |
| Rx errors / high BER at **both** ends | the **cable** (shared element) |
| Errors one direction only, light levels normal (optical) | **ambiguous**: swap transceivers end-for-end to see which way it moves |
| Errors one direction on copper/DAC | **cable** first, then either port |
| IB logical state Init/Armed | **Subnet Manager**, not physical |

Power thresholds come from the transceiver's own alarm/warning thresholds when it reports them. Otherwise nvmon falls back
to `[thresholds]`. Ports that aren't in `links.csv` still get a single-ended verdict, such as "cable or far end".

## Prometheus and Grafana

1. Run `python -m nvmon exporter`. It listens on `127.0.0.1:9877` by default. To expose it, set `listen_address` and
   `NVMON_EXPORTER_TOKEN`.
2. Add [deploy/prometheus/prometheus-scrape.yml](deploy/prometheus/prometheus-scrape.yml) to Prometheus, plus the alert rules in
   [nvmon-alerts.yml](deploy/prometheus/nvmon-alerts.yml).
3. Import [deploy/grafana/nvmon-dashboard.json](deploy/grafana/nvmon-dashboard.json) in Grafana. If you changed
   `metric_prefix`, regenerate it first with `python deploy/grafana/build_dashboard.py --prefix <yours>`.

Main metrics, using the default `nvmon_` prefix:

| Metric | Meaning |
|---|---|
| `nvmon_port_{crc_errors,symbol_errors,fec_uncorrectable,fec_corrected,link_downed,...}_total` | counters; use `rate()` / `increase()` |
| `nvmon_port_{rx,tx}_power_dbm{lane}` | optical power per lane |
| `nvmon_port_module_temperature_celsius`, `nvmon_port_tx_bias_milliamps` | transceiver health |
| `nvmon_port_{effective,raw,symbol}_ber` | bit error ratios |
| `nvmon_port_oper_up` / `nvmon_port_admin_up` | 1 up, 0.5 IB Init, 0 down |
| `nvmon_link_status{link}` | 0 ok, 1 warn, 2 fault |
| `nvmon_link_fault_component{link,component}` | one-hot verdict |
| `nvmon_link_fault_info{link,component,location,summary}` | readable verdict for tables and alerts |
| `nvmon_check_status{device,check}` | health check result |
| `nvmon_up{device}` | 1 if SSH collection worked |

**Without the HTTP exporter:** set `prometheus.outputs = ["textfile"]` and point `textfile_path` at node_exporter's textfile
collector directory, or use `pushgateway` with `nvmon exporter --once` from cron.

## Jira

Jira is off and in dry-run mode by default. To turn it on:

1. Set `[jira]` `url`, `deployment` (`cloud` or `server`), `project_key`, and optionally `issue_type`, `components`,
   `priority_map`, `assignee` and `extra_fields` (custom fields).
2. Export the credentials:
   - Cloud: `NVMON_JIRA_USER` (account email) and `NVMON_JIRA_TOKEN` (API token).
   - Server/DC: `NVMON_JIRA_TOKEN` (personal access token).
3. Run `python -m nvmon jira-test`, then `check --jira-dry-run` to see the payloads.
4. Set `enabled = true` and `dry_run = false`.

**Behavior:**

- One ticket per device (`group_by = "device"`) or per finding/link (`"finding"`), for anything at or above `min_severity`.
- Each ticket carries a fingerprint label `nvmon-<hash>`. While that ticket is open, nvmon **comments** on it when the set
  of findings changes instead of opening a duplicate.
- No run creates more than `max_issues_per_run` tickets.

## Before you trust it: verify on real hardware

The parsers were written from NVIDIA CLI and driver documentation and are tested against **hand-written sample output**
(`tests/`), not captures from real devices. Field names in `nv show ... -o json` change between NVOS and Cumulus releases.
On a lab switch or server:

1. Run `python -m nvmon metrics --device <switch> -v` and compare the Rx/Tx dBm and error counts with
   `nv show interface <port> transceiver` / `counters` on the box.
2. If a command isn't supported on your release, the run records it and moves on. Override the command lists under
   `[metrics]` / `[switch]` in `nvmon.toml`.
3. Paste the real output into `tests/test_metrics.py` so the parsers stay pinned to your releases.

## Tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions (`.github/workflows/ci.yml`) runs the tests on Python 3.11 to 3.13 and checks that the dashboard JSON is up to date.
