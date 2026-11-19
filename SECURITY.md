# Security overview (for internal review)

This page is for the security reviewers who approve nvmon before it's used inside an organization.

## What it does

nvmon is a read-only monitoring tool. It logs into NVIDIA switches and servers over SSH, runs **show / read commands**,
and publishes the results in three places: console/JSON reports, Prometheus metrics, and (optionally) Jira tickets.
It **never changes device configuration**.

## Dependencies

| Package | Why |
|---|---|
| `paramiko` | SSH client (the only third-party runtime dependency) |
| Python standard library | Jira REST, Prometheus exposition/HTTP server, Pushgateway, TOML config |

The repo includes no binaries, no vendored code, and no telemetry back to the author.

## Network flows

| From | To | Port | When |
|---|---|---|---|
| nvmon host | switches / servers (inventory) | TCP 22 (SSH), ICMP | every run / cycle |
| nvmon host | server BMCs (inventory) | ICMP, TCP 443 connect test only (no login) | `check` |
| nvmon host | DNS resolver used by the nvmon host | UDP/TCP 53 | `check` (A/PTR lookups) |
| Prometheus | nvmon host | `prometheus.listen_port` (default 9877), bound to **127.0.0.1** by default | `exporter` with `http` output |
| nvmon host | Pushgateway | HTTPS | only if `pushgateway` output is configured |
| nvmon host | Jira | HTTPS | only if `jira.enabled = true` **and** `jira.dry_run = false` |

nvmon makes no other outbound connections. It honors standard `HTTPS_PROXY` / `NO_PROXY` variables.

## Commands executed on devices

Every command is listed in [nvmon/settings.py](nvmon/settings.py), and you can override any of them in config so security can review
or cut the list down. They're all read-only:

- **NVOS / Cumulus:** `nv show ...`, `ethtool -S|-m <port>`, `ip -d link show <port>`, `l1-show <port>` (sudo).
- **Ubuntu:** `cat /etc/os-release`, `/etc/resolv.conf`, `/sys/...`; `uname`, `uptime`, `hostname`, `getent`, `resolvectl`,
  `ip -br`, `ibdev2netdev`, `ethtool -S|-m` (sudo for `-m`), `ipmitool lan print` (sudo), `mlxlink -m -c -e` (sudo, NVIDIA MFT),
  `nvidia-smi --query-gpu`, `ofed_info -s`.

The commands that need sudo are `ethtool -m`, `ipmitool lan print`, `l1-show` and `mlxlink`. A least-privilege sudoers entry
for the monitoring account looks like this (adjust paths for your distribution):

```
nvmon ALL=(root) NOPASSWD: /usr/sbin/ethtool -m *, /usr/bin/ipmitool lan print *, /usr/bin/mlxlink *
```

If you'd rather grant no sudo at all, remove the `sudo:` entries from the command lists in `nvmon.toml`. You lose module DOM and
BMC LAN readback.

**Injection hardening:** port and HCA names come back from the devices, so they're checked against `^[A-Za-z0-9_.:/@-]+$`
before they go into any command (`nvmon/ssh.py: safe_token`). Hostnames are quoted with `shlex.quote`.

## Secrets

- Secrets are read **only from environment variables**: `NVMON_SSH_PASSWORD*`, `NVMON_JIRA_USER`, `NVMON_JIRA_TOKEN`,
  `NVMON_PUSHGATEWAY_USER`, `NVMON_PUSHGATEWAY_PASSWORD` and `NVMON_EXPORTER_TOKEN`.
- The config loader **refuses** any TOML key that looks like a password, token or secret.
- `nvmon config` prints the effective configuration with secrets shown only as present or absent.
- `--ask-pass` keeps the SSH password in memory only.
- SSH keys and ssh-agent are supported and preferred.
- The inventory CSV contains no credentials.

## Hardening recommendations

1. Set `ssh.host_key_policy = "reject"` and pre-populate `known_hosts`. This is the example config's default.
2. Keep the exporter on `127.0.0.1`, or set `NVMON_EXPORTER_TOKEN` and firewall the port. The token is checked with a
   constant-time compare.
3. Run as a dedicated unprivileged user. The provided [systemd unit](deploy/systemd/nvmon-exporter.service) uses
   `NoNewPrivileges`, `ProtectSystem=strict` and `ProtectHome`.
4. Use a Jira service account with "create issue / add comment" on one project only. Leave `jira.dry_run = true` until
   you've reviewed the payloads (`--jira-dry-run` prints them).
5. `jira.max_issues_per_run` (default 20) caps how many tickets a single run can create, which prevents ticket storms.
6. Set `verify_tls = true` (the default) and `ca_bundle` for internal CAs. Disabling TLS verification has to be done
   explicitly in config.

## Data written to disk

- `reports/<timestamp>/`: JSON results and raw diagnostic output. This can include hostnames, IPs and transceiver serial
  or part numbers.
- `state/jira_state.json`: issue keys and finding digests, used for de-duplication.
- The optional Prometheus textfile.

All of these are git-ignored.
