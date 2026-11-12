#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Scan GitHub repositories for indicators of the November 2026 "wfx" CI secret stealer.

Indicators come from Aikido's write-up:
https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories

The attacker reverts within a minute and deletes the workflow run, so the scan looks
at history (PRs, events, commits, run-number gaps), not only at the current tree.

Usage:
    uv run wfx_scan.py                     # all repos you can access, deep scan of those pushed since 2026-11-10
    uv run wfx_scan.py --all               # deep scan every accessible repo
    uv run wfx_scan.py --org k8up-io --all # one org, every repo
    uv run wfx_scan.py --repo k8up-io/k8up # specific repos
Auth: GITHUB_TOKEN, or the token from `gh auth token`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

API = "https://api.github.com"
SINCE = "2026-11-10T00:00:00Z"

PR_TITLE = "docs: dependency audit notes"
COMMIT_MESSAGES = {
    "ci: refresh build cache",
    "ci: restore",
    "chore: add ci helper",
    "ci: cleanup",
    "chore: add dependency audit workflow",
}
BRANCH_EXACT = {"wfx-docs"}
BRANCH_PATTERNS = [
    re.compile(r"^chore/[a-z0-9]{8}$"),
    re.compile(r"^ci-check-[0-9]{4}$"),
]
WORKFLOW_FILE_PATTERNS = [
    (re.compile(r"^\.github/workflows/build-audit-[A-Za-z0-9]+\.ya?ml$"), "HIGH"),
    # October "GhostActions" wave file names; common enough to be legitimate, so WARN.
    (re.compile(r"^\.github/workflows/(security-audit|audit|ci-check)\.ya?ml$"), "WARN"),
]
OTHER_FILE_PATTERNS = [
    (re.compile(r"^\.ci-[A-Za-z0-9]+\.sh$"), "HIGH"),
    (re.compile(r"(^|/)public/fonts/fa-solid-400\.woff2$"), "WARN"),
]
STEALER_SHA256 = "89695abb392d5cfd4972672961e644bb46baa98aa1ed7173c2a2816c762735cf"
CONTENT_IOCS = [
    ("194.150.166.244", "HIGH"),
    ("18.143.168.96", "HIGH"),
    ("193.32.204.199", "HIGH"),
    ("WF_CALLBACK", "HIGH"),
    ("WF_CTOKEN", "HIGH"),
    ("b42d70a7aab9140ca19e8249", "HIGH"),
    ("<!--WFX-BEGIN-->", "HIGH"),
    ("wfx-loot", "HIGH"),
    ("Restore cache j632", "HIGH"),
    ("#ghc2", "HIGH"),
    ("toJSON(secrets)", "WARN"),
]


def branch_suspicious(name: str) -> bool:
    return name in BRANCH_EXACT or any(p.match(name) for p in BRANCH_PATTERNS)


# --------------------------------------------------------------------------- HTTP


class GitHub:
    def __init__(self, token: str):
        self.token = token
        self.lock = threading.Lock()
        self.calls = 0

    def _req(self, url: str, accept: str = "application/vnd.github+json"):
        if not url.startswith("http"):
            url = API + url
        for attempt in range(5):
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": accept,
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "wfx-scan",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    with self.lock:
                        self.calls += 1
                    return r.status, r.read(), r.headers
            except urllib.error.HTTPError as e:
                with self.lock:
                    self.calls += 1
                if e.code in (403, 429) and (
                    e.headers.get("x-ratelimit-remaining") == "0" or e.headers.get("retry-after")
                ):
                    reset = int(e.headers.get("x-ratelimit-reset", time.time() + 60))
                    wait = int(e.headers.get("retry-after") or max(reset - time.time(), 1)) + 1
                    print(f"  rate limited, sleeping {wait}s", file=sys.stderr)
                    time.sleep(min(wait, 900))
                    continue
                if e.code >= 500 and attempt < 4:
                    time.sleep(2**attempt)
                    continue
                return e.code, e.read(), e.headers
            except (urllib.error.URLError, TimeoutError):
                if attempt < 4:
                    time.sleep(2**attempt)
                    continue
                raise
        raise RuntimeError(f"giving up on {url}")

    def get(self, url: str):
        status, body, _ = self._req(url)
        if status >= 400:
            raise ApiError(status, url, body[:200].decode(errors="replace"))
        return json.loads(body) if body else None

    def paginate(self, url: str, key: str | None = None, stop=None, max_pages: int = 50):
        """Yield items across pages. `stop(item)` returning True ends iteration."""
        sep = "&" if "?" in url else "?"
        if "per_page=" not in url:
            url = f"{url}{sep}per_page=100"
        pages = 0
        while url and pages < max_pages:
            status, body, headers = self._req(url)
            if status >= 400:
                raise ApiError(status, url, body[:200].decode(errors="replace"))
            data = json.loads(body)
            items = data[key] if key else data
            for it in items:
                if stop and stop(it):
                    return
                yield it
            url = None
            for part in (headers.get("Link") or "").split(","):
                m = re.search(r'<([^>]+)>;\s*rel="next"', part)
                if m:
                    url = m.group(1)
            pages += 1


class ApiError(Exception):
    def __init__(self, status, url, body):
        super().__init__(f"{status} {url}: {body}")
        self.status = status


# --------------------------------------------------------------------------- findings


@dataclass
class Finding:
    repo: str
    severity: str  # HIGH, WARN, INFO
    check: str
    detail: str
    url: str = ""


@dataclass
class RepoResult:
    repo: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, sev, check, detail, url=""):
        self.findings.append(Finding(self.repo, sev, check, detail, url))


# --------------------------------------------------------------------------- checks


def check_pulls(gh: GitHub, repo: str, res: RepoResult):
    for pr in gh.paginate(
        f"/repos/{repo}/pulls?state=all&sort=created&direction=desc",
        stop=lambda p: p["created_at"] < SINCE,
        max_pages=10,
    ):
        head = pr["head"]["ref"]
        if pr["title"].strip().lower() == PR_TITLE or branch_suspicious(head):
            res.add(
                "HIGH",
                "probe-pr",
                f"PR #{pr['number']} '{pr['title']}' head={head} by {pr['user']['login']} state={pr['state']}",
                pr["html_url"],
            )


def check_branches(gh: GitHub, repo: str, res: RepoResult) -> list[str]:
    found = []
    for b in gh.paginate(f"/repos/{repo}/branches", max_pages=20):
        if branch_suspicious(b["name"]):
            found.append(b["name"])
            res.add("HIGH" if b["name"] in BRANCH_EXACT else "WARN", "branch", f"branch exists: {b['name']}")
    return found


def check_events(gh: GitHub, repo: str, res: RepoResult):
    """Repo events (last 90 days, max 300) survive branch deletion and reverts."""
    try:
        events = list(gh.paginate(f"/repos/{repo}/events", max_pages=3))
    except ApiError as e:
        res.errors.append(f"events: {e.status}")
        return
    for ev in events:
        if ev["created_at"] < SINCE:
            continue
        t, p, actor = ev["type"], ev.get("payload", {}), ev["actor"]["login"]
        if t in ("CreateEvent", "DeleteEvent") and p.get("ref_type") == "branch" and branch_suspicious(p.get("ref", "")):
            res.add("HIGH", "event-branch", f"{t} branch {p['ref']} by {actor} at {ev['created_at']}")
        elif t == "PushEvent":
            ref = p.get("ref", "").removeprefix("refs/heads/")
            if branch_suspicious(ref):
                res.add("HIGH", "event-push", f"push to {ref} by {actor} at {ev['created_at']}")
            for c in p.get("commits") or []:
                msg = c.get("message", "").splitlines()[0].strip() if c.get("message") else ""
                if msg in COMMIT_MESSAGES:
                    res.add("HIGH", "event-commit", f"pushed commit '{msg}' {c.get('sha', '')[:10]} to {ref} by {actor}")
        elif t == "PullRequestEvent":
            pr = p.get("pull_request", {})
            if (pr.get("title") or "").strip().lower() == PR_TITLE:
                res.add("HIGH", "event-pr", f"PR '{pr.get('title')}' {p.get('action')} by {actor} at {ev['created_at']}")


def check_commits(gh: GitHub, repo: str, res: RepoResult, branches: list[str]):
    for ref in branches:
        try:
            commits = gh.paginate(f"/repos/{repo}/commits?sha={urllib.parse.quote(ref)}&since={SINCE}", max_pages=10)
            for c in commits:
                first = c["commit"]["message"].splitlines()[0].strip() if c["commit"]["message"] else ""
                if first in COMMIT_MESSAGES:
                    who = (c.get("author") or {}).get("login") or c["commit"]["author"]["name"]
                    res.add("HIGH", "commit", f"'{first}' {c['sha'][:10]} on {ref} by {who} at {c['commit']['author']['date']}", c["html_url"])
        except ApiError as e:
            if e.status != 409:  # 409 = empty repo
                res.errors.append(f"commits {ref}: {e.status}")


def check_runs(gh: GitHub, repo: str, res: RepoResult):
    runs = list(gh.paginate(f"/repos/{repo}/actions/runs?created=%3E%3D{SINCE[:10]}", key="workflow_runs", max_pages=10))
    by_wf: dict[int, list[dict]] = {}
    for r in runs:
        by_wf.setdefault(r["workflow_id"], []).append(r)
        head = r.get("head_branch") or ""
        title = (r.get("display_title") or "").strip()
        path = r.get("path") or ""
        if branch_suspicious(head) or title in COMMIT_MESSAGES or title.lower() == PR_TITLE or re.search(r"build-audit-", path):
            res.add("HIGH", "run", f"run {r['name']} #{r['run_number']} branch={head} title='{title}' actor={r['actor']['login']} {r['created_at']}", r["html_url"])
    # Deleted runs leave a hole in the per-workflow run_number sequence.
    for wf_id, rs in by_wf.items():
        nums = sorted({r["run_number"] for r in rs})
        missing = sorted(set(range(nums[0], nums[-1] + 1)) - set(nums))
        if missing:
            res.add("WARN", "run-gap", f"workflow '{rs[0]['name']}' ({rs[0].get('path')}) missing run numbers {missing[:15]}{'...' if len(missing) > 15 else ''} since {SINCE[:10]}")


def check_artifacts_caches(gh: GitHub, repo: str, res: RepoResult):
    try:
        for a in gh.paginate(f"/repos/{repo}/actions/artifacts", key="artifacts", max_pages=5):
            if a["name"].startswith("wfx"):
                res.add("HIGH", "artifact", f"artifact {a['name']} created {a['created_at']}")
    except ApiError as e:
        res.errors.append(f"artifacts: {e.status}")
    try:
        for c in gh.paginate(f"/repos/{repo}/actions/caches", key="actions_caches", max_pages=5):
            if c["key"].startswith("wfx"):
                res.add("HIGH", "cache", f"actions cache {c['key']} ref={c.get('ref')} created {c.get('created_at')}")
    except ApiError as e:
        if e.status not in (403, 404):
            res.errors.append(f"caches: {e.status}")


def blob_text(gh: GitHub, repo: str, sha: str) -> bytes:
    data = gh.get(f"/repos/{repo}/git/blobs/{sha}")
    return base64.b64decode(data["content"]) if data.get("encoding") == "base64" else data["content"].encode()


def scan_content(res: RepoResult, where: str, raw: bytes):
    text = raw.decode(errors="replace")
    for ioc, sev in CONTENT_IOCS:
        if ioc in text:
            res.add(sev, "content", f"{where} contains '{ioc}'")
    if hashlib.sha256(raw).hexdigest() == STEALER_SHA256:
        res.add("HIGH", "content", f"{where} matches stealer SHA256")


def check_tree(gh: GitHub, repo: str, ref: str, res: RepoResult):
    try:
        tree = gh.get(f"/repos/{repo}/git/trees/{urllib.parse.quote(ref)}?recursive=1")
    except ApiError as e:
        if e.status not in (404, 409):
            res.errors.append(f"tree {ref}: {e.status}")
        return
    for ent in tree.get("tree", []):
        if ent["type"] != "blob":
            continue
        path = ent["path"]
        where = f"{ref}:{path}"
        for pat, sev in WORKFLOW_FILE_PATTERNS + OTHER_FILE_PATTERNS:
            if pat.search(path):
                res.add(sev, "file", f"suspicious file {where}")
        is_wf = path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
        is_sh = re.match(r"^\.ci-[A-Za-z0-9]+\.sh$", path)
        if is_wf or is_sh or path in ("package.json", ".vscode/tasks.json"):
            try:
                raw = blob_text(gh, repo, ent["sha"])
            except ApiError as e:
                res.errors.append(f"blob {path}: {e.status}")
                continue
            scan_content(res, where, raw)
            if path == "package.json":
                try:
                    scripts = json.loads(raw).get("scripts", {}) or {}
                except (json.JSONDecodeError, AttributeError):
                    scripts = {}
                for hook in ("preinstall", "install", "postinstall", "prepare"):
                    cmd = scripts.get(hook, "")
                    if ".ci-" in cmd:
                        res.add("HIGH", "npm-hook", f"{where} {hook}: {cmd}")
            if path == ".vscode/tasks.json" and '"folderOpen"' in raw.decode(errors="replace"):
                res.add("WARN", "vscode-task", f"{where} has a runOn folderOpen task")


def deep_scan(gh: GitHub, repo: dict) -> RepoResult:
    name = repo["full_name"]
    res = RepoResult(name)
    steps = [
        ("pulls", lambda: check_pulls(gh, name, res)),
        ("events", lambda: check_events(gh, name, res)),
        ("runs", lambda: check_runs(gh, name, res)),
        ("artifacts", lambda: check_artifacts_caches(gh, name, res)),
    ]
    for label, fn in steps:
        try:
            fn()
        except ApiError as e:
            res.errors.append(f"{label}: {e.status}")
        except Exception as e:  # keep scanning other checks
            res.errors.append(f"{label}: {type(e).__name__}: {e}")
    try:
        sus = check_branches(gh, name, res)
        default = repo.get("default_branch") or "main"
        check_commits(gh, name, res, [default, *sus])
        for ref in [default, *sus]:
            check_tree(gh, name, ref, res)
    except ApiError as e:
        if e.status != 409:
            res.errors.append(f"branches/tree: {e.status}")
    return res


# --------------------------------------------------------------------------- repo discovery


def list_repos(gh: GitHub, args) -> list[dict]:
    repos: dict[str, dict] = {}
    if args.repo:
        for r in args.repo:
            d = gh.get(f"/repos/{r}")
            repos[d["full_name"]] = d
        return list(repos.values())
    if args.org:
        for org in args.org:
            for d in gh.paginate(f"/orgs/{org}/repos?type=all"):
                repos[d["full_name"]] = d
    else:
        for d in gh.paginate("/user/repos?affiliation=owner,collaborator,organization_member", max_pages=200):
            repos[d["full_name"]] = d
        for org in gh.paginate("/user/orgs"):
            try:
                for d in gh.paginate(f"/orgs/{org['login']}/repos?type=all", max_pages=200):
                    repos.setdefault(d["full_name"], d)
            except ApiError as e:
                print(f"  cannot list {org['login']}: {e.status}", file=sys.stderr)
    return list(repos.values())


def search_sweep(gh: GitHub, owners: list[str]) -> list[Finding]:
    """Cheap global pass: the search index catches probe PRs even in repos we skip."""
    out = []
    for owner in owners:
        q = urllib.parse.quote(f'"{PR_TITLE}" in:title is:pr user:{owner} created:>={SINCE[:10]}')
        try:
            for it in gh.paginate(f"/search/issues?q={q}", key="items", max_pages=10):
                repo = it["repository_url"].split("/repos/")[1]
                out.append(Finding(repo, "HIGH", "search-pr", f"PR #{it['number']} '{it['title']}' by {it['user']['login']} state={it['state']}", it["html_url"]))
        except ApiError as e:
            print(f"  search {owner}: {e.status}", file=sys.stderr)
        time.sleep(2.2)  # search API: 30 req/min
    return out


# --------------------------------------------------------------------------- main


def local_checks() -> list[Finding]:
    out = []
    try:
        cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        for ioc in ("#ghc2", "193.32.204.199"):
            if ioc in cron:
                out.append(Finding("localhost", "HIGH", "crontab", f"crontab contains '{ioc}'"))
    except FileNotFoundError:
        pass
    return out


def get_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        return tok
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", action="append", help="limit to an org (repeatable)")
    ap.add_argument("--repo", action="append", help="owner/name (repeatable)")
    ap.add_argument("--all", action="store_true", help="deep scan every repo, not just those pushed since the campaign start")
    ap.add_argument("--always", action="append", default=[], help="org whose repos are always deep scanned (default: k8up-io)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", help="write findings to this JSON file")
    args = ap.parse_args()
    always = set(args.always or ["k8up-io"])

    gh = GitHub(get_token())
    print("Listing repositories...", file=sys.stderr)
    repos = list_repos(gh, args)
    targets = [
        r for r in repos
        if args.all or args.repo or (r.get("pushed_at") or "") >= SINCE or r["owner"]["login"] in always
    ]
    targets = [r for r in targets if not r.get("archived") or (r.get("pushed_at") or "") >= SINCE]
    print(f"{len(repos)} repos accessible, deep scanning {len(targets)}", file=sys.stderr)

    findings: list[Finding] = local_checks()
    owners = sorted({r["owner"]["login"] for r in repos})
    findings += search_sweep(gh, owners)

    errors: dict[str, list[str]] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(deep_scan, gh, r): r["full_name"] for r in targets}
        for f in as_completed(futs):
            done += 1
            try:
                res = f.result()
            except Exception as e:
                errors[futs[f]] = [f"{type(e).__name__}: {e}"]
                continue
            findings += res.findings
            if res.errors:
                errors[res.repo] = res.errors
            flag = " !" if any(x.severity == "HIGH" for x in res.findings) else ""
            print(f"  [{done}/{len(targets)}] {res.repo}{flag}", file=sys.stderr)

    # dedupe search hits that the deep scan also found
    seen, uniq = set(), []
    for f in findings:
        k = (f.repo, f.severity, f.check, f.detail)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    uniq.sort(key=lambda f: ({"HIGH": 0, "WARN": 1}.get(f.severity, 2), f.repo, f.check))

    print()
    print(f"== Findings ({sum(f.severity == 'HIGH' for f in uniq)} HIGH, {sum(f.severity == 'WARN' for f in uniq)} WARN) ==")
    for f in uniq:
        print(f"[{f.severity}] {f.repo} {f.check}: {f.detail} {f.url}".rstrip())
    if errors:
        print(f"\n== Checks that could not run ({len(errors)} repos; treat as unverified) ==")
        for repo, errs in sorted(errors.items()):
            print(f"  {repo}: {', '.join(errs)}")
    print(f"\n{gh.calls} API calls, {len(targets)} repos deep scanned of {len(repos)}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"findings": [f.__dict__ for f in uniq], "errors": errors}, fh, indent=2)
    sys.exit(1 if any(f.severity == "HIGH" for f in uniq) else 0)


if __name__ == "__main__":
    main()
