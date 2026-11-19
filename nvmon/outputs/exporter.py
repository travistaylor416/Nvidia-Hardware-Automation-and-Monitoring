"""
Long-running exporter: collect -> isolate -> publish, every settings.prometheus.interval seconds.

    GET /metrics   Prometheus text format (requires "Authorization: Bearer $NVMON_EXPORTER_TOKEN" if set)
    GET /healthz   200 once the first cycle finished

Optionally runs the full health checks every N cycles and raises Jira tickets.
"""

import hmac
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import settings as settings_mod
from ..checks import run_device_checks
from ..metrics.collect import collect_device
from ..metrics.isolate import analyze
from . import prometheus

log = logging.getLogger(__name__)


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.text = ""
        self.ready = False
        self.previous = {}
        self.reports = []


def run_cycle(devices, links, s, state, cycle, jira_cb=None):
    started = time.time()
    device_status, samples = {}, []

    def one(device):
        t0 = time.time()
        got, err = collect_device(device, links, s)
        if err:
            log.warning("%s: collection failed: %s", device.name, err)
        return device, got, err, time.time() - t0

    with ThreadPoolExecutor(max_workers=max(1, s.general.workers)) as pool:
        for device, got, err, dur in pool.map(one, devices):
            samples += got
            device_status[device.name] = {"role": device.role, "os": device.os, "up": err is None,
                                          "duration": round(dur, 3), "timestamp": time.time()}

    results = analyze(samples, links, s.thresholds, previous=state.previous)
    state.previous = {(smp.device, smp.port): smp for smp in samples}

    p = s.prometheus
    if p.include_health_checks and cycle % max(1, p.health_check_every) == 0:
        with ThreadPoolExecutor(max_workers=max(1, s.general.workers)) as pool:
            state.reports = list(pool.map(lambda d: run_device_checks(d, s), devices))

    text = prometheus.build(samples, results, device_status, state.reports)
    with state.lock:
        state.text, state.ready = text, True
    for line in prometheus.deliver(text, s):
        log.info(line)
    if jira_cb:
        jira_cb(state.reports if cycle % max(1, p.health_check_every) == 0 else [], results)
    log.info("cycle %d: %d devices, %d ports, %d links in %.1fs", cycle, len(devices), len(samples),
             len(results), time.time() - started)
    return results


def make_handler(state, token):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.split("?")[0] == "/healthz":
                self._send(200 if state.ready else 503, b"ok\n" if state.ready else b"starting\n")
                return
            if self.path.split("?")[0] != "/metrics":
                self._send(404, b"not found\n")
                return
            if token:
                got = self.headers.get("Authorization", "")
                if not hmac.compare_digest(got, f"Bearer {token}"):
                    self._send(401, b"unauthorized\n")
                    return
            with state.lock:
                body = state.text.encode()
            self._send(200, body, "text/plain; version=0.0.4; charset=utf-8")

        def _send(self, code, body, ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            log.debug("http %s - " + fmt, self.client_address[0], *args)

    return Handler


def serve(devices, links, s=None, jira_cb=None, once=False):
    s = s or settings_mod.current()
    state = State()
    server = None
    if "http" in s.prometheus.outputs and not once:
        token = settings_mod.secret("exporter_token")
        server = ThreadingHTTPServer((s.prometheus.listen_address, s.prometheus.listen_port), make_handler(state, token))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"nvmon exporter listening on http://{s.prometheus.listen_address}:{s.prometheus.listen_port}/metrics"
              + (" (bearer token required)" if token else ""))
    cycle = 0
    try:
        while True:
            t0 = time.time()
            try:
                run_cycle(devices, links, s, state, cycle, jira_cb)
            except Exception:  # noqa: BLE001 - keep the exporter alive
                log.exception("collection cycle failed")
            cycle += 1
            if once:
                return state
            time.sleep(max(1, s.prometheus.interval - (time.time() - t0)))
    except KeyboardInterrupt:
        print("exporter stopped")
    finally:
        if server:
            server.shutdown()
    return state
