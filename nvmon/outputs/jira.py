"""
Jira ticketing (Jira Cloud or Jira Server / Data Center) using only the Python standard library.

Safety defaults for corporate use:
    * jira.enabled = false and jira.dry_run = true until you change them
    * at most jira.max_issues_per_run new issues per run
    * de-duplication: each ticket carries a fingerprint label (nvmon-<hash>); while an issue with that
      label is open, nvmon comments on it (only when the set of findings changed) instead of creating another

Auth:
    cloud   NVMON_JIRA_USER (account email) + NVMON_JIRA_TOKEN (API token)  -> HTTP Basic
    server  NVMON_JIRA_TOKEN (personal access token)                        -> Bearer
HTTPS proxies are honored via the standard HTTPS_PROXY / NO_PROXY environment variables.
"""

import base64
import hashlib
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from .. import __version__
from .. import settings as settings_mod
from ..models import FAIL, SEVERITY, WARN, Finding
from .prometheus import ssl_context


# --------------------------------------------------------------------------- findings


def findings_from(reports=(), link_results=()):
    found = []
    for rep in reports:
        for chk in rep.problems():
            detail = chk.detail
            if chk.name == "Ports" and rep.port_diags:
                detail += "\n" + "\n".join(f"  port {d.port} ({d.state}): {'; '.join(d.hints)}" for d in rep.port_diags)
            found.append(Finding(f"check|{rep.name}|{chk.name}", rep.name, chk.status,
                                 f"{rep.name}: {chk.name}", detail))
    for lr in link_results:
        if lr.status not in (WARN, FAIL):
            continue
        detail = "\n".join([f"Suspected: {lr.location or lr.component}", *[f"  - {e}" for e in lr.evidence],
                            f"Action: {lr.action}" if lr.action else ""]).strip()
        found.append(Finding(f"link|{lr.link_id}", lr.a_device, lr.status,
                             f"{lr.link_id}: {lr.location or lr.summary}", detail))
    return found


def fingerprint(key):
    return "nvmon-" + hashlib.sha1(key.encode()).hexdigest()[:12]


def group_findings(findings, j):
    floor = SEVERITY.get(j.min_severity.upper(), 2)
    groups = {}
    for f in findings:
        if SEVERITY[f.severity] < floor:
            continue
        gkey = f"device|{f.device}" if j.group_by == "device" else f.key
        groups.setdefault(gkey, []).append(f)
    return groups


def render(group_key, items, j):
    sev = FAIL if any(f.severity == FAIL for f in items) else WARN
    if j.group_by == "device":
        device = items[0].device
        summary = f"{j.summary_prefix} {device}: {len(items)} problem(s) - " + ", ".join(
            f.title.split(": ", 1)[-1] for f in items[:3]) + ("..." if len(items) > 3 else "")
    else:
        summary = f"{j.summary_prefix} {items[0].title}"
    lines = [f"nvmon {__version__} detected the following on {datetime.now():%Y-%m-%d %H:%M:%S} "
             f"(collector host: {socket.gethostname()}):", ""]
    for f in items:
        lines.append(f"[{f.severity}] {f.title}")
        lines += [f"    {ln}" for ln in f.detail.splitlines() if ln.strip()]
        lines.append("")
    lines.append(f"Fingerprint: {fingerprint(group_key)} - nvmon updates this issue instead of opening duplicates.")
    digest = hashlib.sha1("|".join(sorted(f"{f.key}={f.severity}" for f in items)).encode()).hexdigest()
    return sev, summary[:250], "\n".join(lines), digest


# --------------------------------------------------------------------------- client


class JiraError(RuntimeError):
    pass


class JiraClient:
    def __init__(self, j, user=None, token=None, opener=None):
        if not j.url:
            raise JiraError("jira.url is not set")
        self.j = j
        self.base = j.url.rstrip("/")
        self.api = f"{self.base}/rest/api/{j.api_version}"
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if j.deployment == "cloud":
            if not (user and token):
                raise JiraError("Jira Cloud needs NVMON_JIRA_USER and NVMON_JIRA_TOKEN")
            self.headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        else:
            if not token:
                raise JiraError("Jira Server/DC needs NVMON_JIRA_TOKEN (personal access token)")
            self.headers["Authorization"] = f"Bearer {token}"
        self._open = opener or urllib.request.urlopen
        self._ctx = ssl_context(j.verify_tls, j.ca_bundle)

    def request(self, method, path, body=None, query=None):
        url = (path if path.startswith("http") else f"{self.api}{path}")
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=self.headers)
        try:
            with self._open(req, timeout=self.j.timeout, context=self._ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise JiraError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise JiraError(f"{method} {path} -> {exc.reason}") from exc

    def whoami(self):
        return self.request("GET", "/myself")

    def find_open(self, label):
        jql = (f'project = "{self.j.project_key}" AND labels = "{label}" '
               f"AND statusCategory != Done ORDER BY created DESC")
        query = {"jql": jql, "fields": "summary,status", "maxResults": 1}
        path = "/search/jql" if self.j.deployment == "cloud" else "/search"
        issues = self.request("GET", path, query=query).get("issues", [])
        return issues[0]["key"] if issues else None

    def create(self, fields):
        return self.request("POST", "/issue", {"fields": fields}).get("key")

    def comment(self, key, text):
        self.request("POST", f"/issue/{key}/comment", {"body": text_body(self.j, text)})


def text_body(j, text):
    if str(j.api_version) == "3":  # Atlassian Document Format
        return {"type": "doc", "version": 1, "content": [
            {"type": "codeBlock", "content": [{"type": "text", "text": text}]}]}
    return "{noformat}\n" + text + "\n{noformat}"


def build_fields(j, summary, description, severity, label):
    fields = {
        "project": {"key": j.project_key},
        "issuetype": {"name": j.issue_type},
        "summary": summary,
        "description": text_body(j, description),
        "labels": list(dict.fromkeys([*j.labels, label])),
    }
    if j.components:
        fields["components"] = [{"name": c} for c in j.components]
    if j.set_priority and j.priority_map.get(severity):
        fields["priority"] = {"name": j.priority_map[severity]}
    if j.assignee:
        fields["assignee"] = {"accountId": j.assignee} if j.deployment == "cloud" else {"name": j.assignee}
    fields.update(j.extra_fields)
    return fields


# --------------------------------------------------------------------------- orchestration


def _state_path(s):
    return Path(s.general.state_dir) / "jira_state.json"


def _load_state(s):
    try:
        return json.loads(_state_path(s).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(s, state):
    path = _state_path(s)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def raise_tickets(findings, s=None, client=None, force_dry_run=False):
    """Create/update Jira issues for findings. Returns human-readable result lines."""
    s = s or settings_mod.current()
    j = s.jira
    groups = group_findings(findings, j)
    if not groups:
        return ["jira: nothing at or above min_severity " + j.min_severity]
    dry = j.dry_run or force_dry_run
    if not j.enabled and not dry:
        return ["jira: disabled (set jira.enabled = true)"]
    if not j.project_key:
        return ["jira: jira.project_key is not set"]

    if client is None and not dry:
        client = JiraClient(j, settings_mod.secret("jira_user"), settings_mod.secret("jira_token"))
    state = _load_state(s)
    out, created = [], 0

    for gkey, items in sorted(groups.items()):
        label = fingerprint(gkey)
        sev, summary, description, digest = render(gkey, items, j)
        fields = build_fields(j, summary, description, sev, label)
        if dry:
            out.append(f"jira DRY RUN would create/update [{label}] {summary}")
            out.append("    payload: " + json.dumps({"fields": fields})[:600])
            continue
        try:
            existing = client.find_open(label) if j.dedupe else None
            if existing:
                prev = state.get(label, {})
                if j.comment_on_change and prev.get("digest") != digest:
                    client.comment(existing, "Findings changed:\n\n" + description)
                    out.append(f"jira: commented on {existing} ({summary})")
                else:
                    out.append(f"jira: {existing} already open, unchanged")
                state[label] = {"key": existing, "digest": digest, "updated": time.time()}
                continue
            if created >= j.max_issues_per_run:
                out.append(f"jira: max_issues_per_run={j.max_issues_per_run} reached, skipped {summary}")
                continue
            key = client.create(fields)
            created += 1
            state[label] = {"key": key, "digest": digest, "updated": time.time()}
            out.append(f"jira: created {key} {summary}")
        except JiraError as exc:
            out.append(f"jira FAILED for {summary}: {exc}")
    if not dry:
        _save_state(s, state)
    return out
