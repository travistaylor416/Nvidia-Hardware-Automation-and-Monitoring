"""Checks run from the monitoring host itself (Windows, Linux, macOS)."""

import platform
import socket
import subprocess

from . import settings as settings_mod


def ping(host, count=None, timeout=None):
    if not host:
        return False
    s = settings_mod.current().checks
    count = count or s.ping_count
    timeout = timeout or s.ping_timeout
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    # Windows returns 0 for "Destination host unreachable" replies, so also require a TTL.
    return result.returncode == 0 and "ttl=" in result.stdout.lower()


def tcp_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def forward_lookup(name):
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)})
    except socket.gaierror:
        return []


def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""
