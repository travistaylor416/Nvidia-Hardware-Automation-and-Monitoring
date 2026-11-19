"""Thin paramiko wrapper: one connection per device, single / sudo / batched commands."""

import logging
import re
import shlex
from dataclasses import dataclass

from . import settings as settings_mod

log = logging.getLogger(__name__)

# Filled by the CLI's --ask-pass so every device can share one prompt (kept in memory only).
PROMPTED_PASSWORD = None

# Port names come from remote devices; only allow safe characters before putting them in a command.
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/@-]+$")
MARK = "@@NVMON@@"


def safe_token(value):
    value = str(value)
    if not SAFE_TOKEN.match(value):
        raise ValueError(f"refusing unsafe token in command: {value!r}")
    return value


@dataclass
class CmdResult:
    command: str
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self):
        return self.rc == 0

    @property
    def text(self):
        return self.stdout or self.stderr


class SSHSession:
    def __init__(self, host, username, password=None, settings=None):
        self.s = settings or settings_mod.current()
        self.host = host
        self.username = username
        self.password = password
        self.client = None

    def __enter__(self):
        import paramiko  # lazy: parsers/tests work without it

        policies = {"auto": paramiko.AutoAddPolicy, "warn": paramiko.WarningPolicy, "reject": paramiko.RejectPolicy}
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        if self.s.ssh.known_hosts:
            self.client.load_host_keys(self.s.ssh.known_hosts)
        self.client.set_missing_host_key_policy(policies.get(self.s.ssh.host_key_policy, paramiko.WarningPolicy)())
        t = self.s.ssh.timeout
        self.client.connect(
            hostname=self.host, port=self.s.ssh.port, username=self.username, password=self.password,
            key_filename=self.s.ssh.key_file or None, look_for_keys=self.password is None, allow_agent=True,
            timeout=t, banner_timeout=t, auth_timeout=t,
        )
        return self

    def __exit__(self, *exc):
        if self.client:
            self.client.close()

    def run(self, command, timeout=None, _stdin_data=None):
        log.debug("%s$ %s", self.host, command)
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout or self.s.ssh.command_timeout)
        if _stdin_data is not None:
            stdin.write(_stdin_data)
            stdin.flush()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        rc = stdout.channel.recv_exit_status()
        return CmdResult(command, rc, out, err)

    def sudo(self, command, timeout=None):
        inner = shlex.quote(command)
        if self.password:
            return self.run(f"sudo -S -p '' sh -c {inner}", timeout, _stdin_data=self.password + "\n")
        return self.run(f"sudo -n sh -c {inner}", timeout)

    def run_any(self, command, timeout=None):
        """Config-style command: a 'sudo:' prefix means run through sudo."""
        if command.startswith("sudo:"):
            return self.sudo(command[5:].strip(), timeout)
        return self.run(command, timeout)

    def run_many(self, commands, batch=True, timeout=None):
        """Run many config-style commands; batched into at most two execs (plain + sudo) when allowed."""
        if not batch:
            return [self.run_any(c, timeout) for c in commands]
        results = [None] * len(commands)
        groups = {False: [], True: []}
        for i, cmd in enumerate(commands):
            is_sudo = cmd.startswith("sudo:")
            groups[is_sudo].append((i, cmd[5:].strip() if is_sudo else cmd))
        for is_sudo, items in groups.items():
            if not items:
                continue
            script = "; ".join(f"echo '{MARK} {n}'; {cmd} 2>&1; echo \"{MARK} rc $?\"" for n, (_, cmd) in enumerate(items))
            res = self.sudo(script, timeout) if is_sudo else self.run(f"sh -c {shlex.quote(script)}", timeout)
            parsed = parse_batch(res.stdout, len(items))
            for n, (i, cmd) in enumerate(items):
                if parsed[n] is None:
                    results[i] = CmdResult(cmd, res.rc or 1, "", res.text or "batch produced no output")
                else:
                    rc, out = parsed[n]
                    results[i] = CmdResult(cmd, rc, out, "" if rc == 0 else out)
        return results


def parse_batch(text, count):
    out = [None] * count
    current, lines = None, []
    for line in text.splitlines():
        if line.startswith(MARK):
            parts = line.split()
            if len(parts) == 3 and parts[1] == "rc" and current is not None:
                out[current] = (int(parts[2]) if parts[2].isdigit() else 1, "\n".join(lines).strip())
                current, lines = None, []
            elif len(parts) == 2 and parts[1].isdigit():
                current, lines = int(parts[1]), []
        elif current is not None:
            lines.append(line)
    return out


def open_session(device, settings=None):
    password = settings_mod.secret("ssh_password", device.os) or PROMPTED_PASSWORD
    return SSHSession(device.mgmt_address, device.username, password=password, settings=settings)
