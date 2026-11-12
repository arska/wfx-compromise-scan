# gh-compromise-scan

Scans the GitHub repositories you can access for indicators of the November 2026 "wfx" CI secret stealer. Compromised accounts pushed it to tens of thousands of repositories, as described in Aikido's write-up:
<https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories>

The attacker reverts the change within about a minute and deletes the workflow run and its logs, so the current tree is usually clean. The scanner therefore looks at history: pull requests, repository events, commits, workflow run numbers, artifacts and caches.

## Usage

Requires [uv](https://docs.astral.sh/uv/) and a GitHub token with `repo` scope, taken from `GITHUB_TOKEN`/`GH_TOKEN` or from `gh auth token`. The script uses only the standard library.

```bash
uv run wfx_scan.py                        # every accessible repo; deep scan of those pushed since 2026-11-10
uv run wfx_scan.py --all                  # deep scan every accessible repo
uv run wfx_scan.py --org k8up-io --all    # one org
uv run wfx_scan.py --repo owner/name      # specific repos (repeatable)
uv run wfx_scan.py --json findings.json   # also write machine-readable output
```

Without `--all`, a repo is only deep scanned if it has been pushed since the campaign started, or if its owner is listed with `--always` (default: `k8up-io`). Every branch push, revert and branch deletion updates `pushed_at`, so a repo the attacker touched cannot sit below that cutoff. A search-API sweep for the probe PR title runs across all owners regardless.

The exit code is 1 if any HIGH finding exists and 0 otherwise.

## What it checks

| Check | Signal | Severity |
|---|---|---|
| `probe-pr`, `search-pr`, `event-pr` | PR titled `docs: dependency audit notes`, or head branch matching the patterns below | HIGH |
| `branch`, `event-branch`, `event-push` | Branch `wfx-docs` (HIGH); `chore/[a-z0-9]{8}`, `ci-check-[0-9]{4}` (WARN when only the branch exists) | HIGH/WARN |
| `commit`, `event-commit` | Commit messages `ci: refresh build cache`, `ci: restore`, `chore: add ci helper`, `ci: cleanup`, `chore: add dependency audit workflow` since 2026-11-10 | HIGH |
| `run` | Workflow runs since 2026-11-10 on a suspicious branch, with a matching title, or from `build-audit-*` | HIGH |
| `run-gap` | Missing run numbers per workflow since 2026-11-10 (deleted runs). Aikido calls this the strongest remaining trace, but maintainers delete runs too | WARN |
| `artifact`, `cache` | Artifacts or Actions caches named `wfx*` (e.g. `wfx-loot-<run id>`) | HIGH |
| `file` | `.github/workflows/build-audit-*.yml`, `.ci-*.sh` (HIGH); October wave names `security-audit.yml`, `audit.yml`, `ci-check.yml`, `public/fonts/fa-solid-400.woff2` (WARN) | HIGH/WARN |
| `content` | Workflows, `.ci-*.sh`, `package.json`, `.vscode/tasks.json` containing the exfil IPs `194.150.166.244`, `18.143.168.96`, `193.32.204.199`, `WF_CALLBACK`, `WF_CTOKEN`, `<!--WFX-BEGIN-->`, `wfx-loot`, `Restore cache j632`, `#ghc2`, or the stealer SHA256; `toJSON(secrets)` is WARN | HIGH/WARN |
| `npm-hook` | `preinstall`/`install`/`postinstall`/`prepare` script running a `.ci-*` file | HIGH |
| `vscode-task` | `.vscode/tasks.json` with a `folderOpen` task | WARN |
| `crontab` | Local crontab containing `#ghc2` or `193.32.204.199` | HIGH |

Content and file checks run against the default branch and any suspicious branch that still exists.

## Limits

- The repository events API returns at most 300 events from the last 90 days, so busy repos may have dropped the relevant ones.
- Since August 2025, GitHub has been dropping commit lists from `PushEvent` payloads, so the scanner reads commit messages from the commits API, which covers the default branch and surviving suspicious branches only. A commit on a deleted branch shows up only through its events or workflow runs.
- Cloud-side persistence is not checked: AWS roles with `"Principal": {"AWS": "*"}` trust, IAM access keys created by the campaign, Azure federated identity credentials named `wfx-ci-*`, and forged `success` commit statuses. Check those in the cloud consoles.
- Any check that failed (for example 404 on Actions for a repo without it) is listed under "Checks that could not run". Treat those repos as unverified, not clean.

## If something is found

Assume every secret, variable and cloud role reachable from that repo's workflows is compromised and rotate it. Close the probe PRs, delete the branches, and look for the cloud persistence listed above.

## Output

Scan results name private repositories. The `.gitignore` excludes `*.json`, `*.txt` and `*.err` so they are not committed by accident.
