#!/usr/bin/env python3
"""Shared DefectDojo uploader for all Cenefits/Offmon CI pipelines.

What it does, per --scan tuple:
  1. POST /api/v2/import-scan/ (multipart) with auto_create_context=true,
     active=true, verified=true, push_to_jira=true, close_old_findings=true.
     DefectDojo creates/reuses the engagement+test and asynchronously pushes
     each finding to the SVM Jira board (project/environment/priority/due-date
     labels are written NATIVELY by DefectDojo's Jira integration).
  2. For every finding produced by that import, poll
     /api/v2/jira_finding_mappings/?finding=<id> until the async push has
     created the Jira issue (jira_key appears), then PATCH that issue via
     PUT /rest/api/3/issue/<key> using the Jira `update.labels[].add` op so the
     DYNAMIC per-finding labels `vuln:<label>` and `component:<label>` are
     ADDED WITHOUT removing the labels DefectDojo already set (project:*, CVE).

Design rules:
  * This is a reporting side-channel. It must NEVER fail the build:
    a missing report is warned-and-skipped; any HTTP/Jira error is logged and
    swallowed; the process always exits 0.
  * All connection details come from the environment so the same script works
    for every product/branch.

Environment variables:
  DEFECTDOJO_URL        e.g. https://dojo.tail51f86.ts.net (Tailscale-only)
  DEFECTDOJO_API_TOKEN  DefectDojo API v2 token
  JIRA_URL              e.g. https://teomach.atlassian.net
  JIRA_USER             Jira account email (basic auth user)
  JIRA_API_TOKEN        Jira API token (basic auth password)

CLI:
  dojo_upload.py \
    --product-name "Cenefits Staging" \
    --engagement "CI - backend" \
    --branch develop \
    --commit "$GITHUB_SHA" \
    --scan "bandit.json:Bandit Scan:sast:backend" \
    --scan "grype.json:Anchore Grype:dependency:backend" \
    --scan "trufflehog-backend.json:Trufflehog Scan:secret:backend"

Each --scan tuple is "file:scan_type:vuln_label:component_label".
  file              path to the report on disk (missing -> warn+skip)
  scan_type         exact DefectDojo parser name ("Bandit Scan", "Anchore Grype",
                    "Trufflehog Scan", "CycloneDX Scan", "Checkov Scan",
                    "Gitleaks Scan", "ZAP Scan", "Generic Findings Import", ...)
  vuln_label        value for the `vuln:<...>` Jira label (e.g. sast, secret,
                    dependency, iac, dast, runtime)
  component_label   value for the `component:<...>` Jira label
                    (e.g. backend, frontend, auth-ms)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:  # pragma: no cover - dependency is installed by the action
    sys.stderr.write("dojo_upload: the 'requests' package is required\n")
    raise

# How long to wait for DefectDojo's async (celery) push_to_jira to create the
# Jira issue before giving up on a single finding, and how often to re-check.
JIRA_MAPPING_TIMEOUT_S = float(os.environ.get("DOJO_JIRA_TIMEOUT", "180"))
JIRA_MAPPING_POLL_INTERVAL_S = float(os.environ.get("DOJO_JIRA_POLL", "5"))
# Cap per-import finding processing so a noisy scan can't stall the build.
MAX_FINDINGS_PER_IMPORT = int(os.environ.get("DOJO_MAX_FINDINGS", "500"))
HTTP_TIMEOUT_S = float(os.environ.get("DOJO_HTTP_TIMEOUT", "60"))


def log(msg: str) -> None:
    print(f"[dojo-upload] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[dojo-upload][WARN] {msg}", flush=True)


class Config:
    """Resolved connection settings from the environment."""

    def __init__(self) -> None:
        self.dojo_url = (os.environ.get("DEFECTDOJO_URL") or "").rstrip("/")
        self.dojo_token = os.environ.get("DEFECTDOJO_API_TOKEN") or ""
        self.jira_url = (os.environ.get("JIRA_URL") or "").rstrip("/")
        self.jira_user = os.environ.get("JIRA_USER") or ""
        self.jira_token = os.environ.get("JIRA_API_TOKEN") or ""

    @property
    def dojo_ready(self) -> bool:
        return bool(self.dojo_url and self.dojo_token)

    @property
    def jira_ready(self) -> bool:
        return bool(self.jira_url and self.jira_user and self.jira_token)


def parse_scan_tuple(raw: str) -> tuple[str, str, str, str] | None:
    """Parse 'file:scan_type:vuln_label:component_label'.

    Only the first three colons are treated as separators so file paths and
    scan-type names that themselves contain no colon work; paths with colons
    are not supported (none of ours have them).
    """
    parts = raw.split(":")
    if len(parts) < 4:
        warn(
            f"ignoring malformed --scan '{raw}' "
            "(expected file:scan_type:vuln_label:component_label)"
        )
        return None
    # Rejoin any trailing fragments into the component label so unexpected
    # extra colons land in the last field rather than dropping data.
    file_path, scan_type, vuln_label = parts[0], parts[1], parts[2]
    component_label = ":".join(parts[3:])
    return file_path.strip(), scan_type.strip(), vuln_label.strip(), component_label.strip()


# Report fields that may carry a raw secret value; scrubbed before upload so
# secret scanners never ship the secret itself into DefectDojo/Jira.
_SECRET_FIELDS = ("Secret", "Match", "Raw", "RawV2", "Redacted", "line", "secret", "raw")
_SECRET_SCAN_TYPES = ("Trufflehog Scan", "Gitleaks Scan")


def redact_secret_report(file_path: str, scan_type: str) -> str:
    """For secret scanners, return a path to a copy with secret values masked.

    gitleaks supports --redact at scan time, but we re-scrub here regardless so a
    misconfigured scanner can't leak a secret value into a finding/Jira ticket.
    Handles both a single JSON document (gitleaks array) and newline-delimited
    JSON (trufflehog JSONL) — a plain json.load() throws on JSONL and would
    otherwise return the file UNREDACTED. Non-secret scan types are unchanged.
    """
    if scan_type not in _SECRET_SCAN_TYPES:
        return file_path
    try:
        with open(file_path) as fh:
            raw = fh.read()
    except OSError:
        return file_path
    if not raw.strip():
        return file_path  # empty report; let import_scan skip it

    def scrub(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if k in _SECRET_FIELDS and isinstance(v, str) and v:
                    node[k] = "REDACTED"
                else:
                    scrub(v)
        elif isinstance(node, list):
            for item in node:
                scrub(item)

    # Try a single JSON document first (gitleaks); fall back to JSONL (trufflehog).
    try:
        payload = json.loads(raw)
        scrub(payload)
        out = json.dumps(payload)
    except ValueError:
        lines = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                # Drop an unparseable line rather than risk leaking a raw secret.
                continue
            scrub(obj)
            lines.append(json.dumps(obj))
        out = "\n".join(lines)

    redacted = file_path + ".redacted.json"
    try:
        with open(redacted, "w") as fh:
            fh.write(out)
    except OSError:
        return file_path
    return redacted


def import_scan(
    session: requests.Session,
    cfg: Config,
    *,
    product_name: str,
    engagement: str,
    branch: str,
    commit: str,
    file_path: str,
    scan_type: str,
    vuln_label: str,
    component_label: str,
) -> int | None:
    """POST one report to DefectDojo. Returns the test_id or None on failure."""
    url = f"{cfg.dojo_url}/api/v2/import-scan/"
    # Mask secret values for secret scanners before the report leaves the runner.
    file_path = redact_secret_report(file_path, scan_type)
    data = {
        "scan_type": scan_type,
        "product_name": product_name,
        "engagement_name": engagement,
        "auto_create_context": "true",
        "active": "true",
        "verified": "true",
        "push_to_jira": "true",
        "close_old_findings": "true",
        # One SVM Jira ticket PER FINDING (no group_by). Finding-group collapsing
        # was intentionally rejected — we want per-finding tickets.
        "branch_tag": branch,
        "commit_hash": commit,
        # 'service' is DefectDojo's microservice/area field (filterable + its own
        # view) — populated from our component dimension so it isn't empty.
        "service": component_label,
        # Tags are stored on the test/findings; helpful for triage even though
        # DefectDojo will not push them to Jira (that is what this script does).
        "tags": f"vuln:{vuln_label},component:{component_label},branch:{branch}",
    }
    try:
        with open(file_path, "rb") as fh:
            files = {"file": (os.path.basename(file_path), fh)}
            resp = session.post(url, data=data, files=files, timeout=HTTP_TIMEOUT_S)
    except OSError as exc:
        warn(f"could not read report '{file_path}': {exc}; skipping")
        return None
    except requests.RequestException as exc:
        warn(f"import-scan request failed for '{file_path}': {exc}; skipping")
        return None

    if resp.status_code not in (200, 201):
        warn(
            f"import-scan for '{file_path}' returned HTTP {resp.status_code}: "
            f"{resp.text[:500]}; skipping"
        )
        return None

    try:
        payload = resp.json()
    except ValueError:
        warn(f"import-scan for '{file_path}' returned non-JSON body; skipping")
        return None

    test_id = payload.get("test") or payload.get("test_id")
    engagement_id = payload.get("engagement") or payload.get("engagement_id")
    log(
        f"imported '{file_path}' as '{scan_type}' "
        f"(engagement={engagement_id}, test={test_id})"
    )
    try:
        return int(test_id) if test_id is not None else None
    except (TypeError, ValueError):
        return None


def list_findings_for_test(
    session: requests.Session, cfg: Config, test_id: int
) -> list[int]:
    """Return the finding ids created/affected by an import's test."""
    findings: list[int] = []
    url = f"{cfg.dojo_url}/api/v2/findings/"
    params = {"test": test_id, "limit": 100}
    try:
        while url and len(findings) < MAX_FINDINGS_PER_IMPORT:
            resp = session.get(url, params=params, timeout=HTTP_TIMEOUT_S)
            if resp.status_code != 200:
                warn(
                    f"listing findings for test {test_id} returned "
                    f"HTTP {resp.status_code}; stopping enumeration"
                )
                break
            body = resp.json()
            for item in body.get("results", []):
                fid = item.get("id")
                if isinstance(fid, int):
                    findings.append(fid)
            # Follow DRF pagination; params only apply to the first page.
            url = body.get("next")
            params = None
    except (requests.RequestException, ValueError) as exc:
        warn(f"could not enumerate findings for test {test_id}: {exc}")
    return findings[:MAX_FINDINGS_PER_IMPORT]


def wait_for_jira_key(
    session: requests.Session, cfg: Config, finding_id: int
) -> str | None:
    """Poll the jira_finding_mappings endpoint until the async push lands.

    Returns the Jira issue key (e.g. 'SVM-123') or None on timeout/error.
    """
    url = f"{cfg.dojo_url}/api/v2/jira_finding_mappings/"
    deadline = time.monotonic() + JIRA_MAPPING_TIMEOUT_S
    while True:
        try:
            resp = session.get(
                url, params={"finding": finding_id}, timeout=HTTP_TIMEOUT_S
            )
            if resp.status_code == 200:
                for item in resp.json().get("results", []):
                    key = item.get("jira_key")
                    if key:
                        return key
            else:
                warn(
                    f"jira_finding_mappings for finding {finding_id} returned "
                    f"HTTP {resp.status_code}"
                )
        except (requests.RequestException, ValueError) as exc:
            warn(f"polling jira mapping for finding {finding_id} failed: {exc}")
        if time.monotonic() >= deadline:
            warn(
                f"timed out waiting for Jira issue for finding {finding_id} "
                f"after {JIRA_MAPPING_TIMEOUT_S:.0f}s"
            )
            return None
        time.sleep(JIRA_MAPPING_POLL_INTERVAL_S)


def add_jira_labels(
    cfg: Config, issue_key: str, labels: list[str]
) -> bool:
    """Add labels to a Jira issue without touching existing ones.

    Uses the Jira Cloud REST v3 `update` block with the `add` verb so each
    label is appended; DefectDojo's native labels (project:*, CVE) are kept.
    """
    if not labels:
        return True
    url = f"{cfg.jira_url}/rest/api/3/issue/{issue_key}"
    body = {"update": {"labels": [{"add": label} for label in labels]}}
    try:
        resp = requests.put(
            url,
            json=body,
            auth=(cfg.jira_user, cfg.jira_token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=HTTP_TIMEOUT_S,
        )
    except requests.RequestException as exc:
        warn(f"PUT labels on {issue_key} failed: {exc}")
        return False
    # 204 No Content is the success response for a Jira issue edit.
    if resp.status_code in (200, 204):
        log(f"labelled {issue_key} with {labels}")
        return True
    warn(
        f"labelling {issue_key} returned HTTP {resp.status_code}: "
        f"{resp.text[:300]}"
    )
    return False


def process_scan(
    session: requests.Session,
    cfg: Config,
    *,
    product_name: str,
    engagement: str,
    branch: str,
    commit: str,
    file_path: str,
    scan_type: str,
    vuln_label: str,
    component_label: str,
) -> None:
    if not os.path.isfile(file_path):
        warn(f"report '{file_path}' not found; skipping this scan")
        return
    if os.path.getsize(file_path) == 0:
        warn(f"report '{file_path}' is empty; skipping this scan")
        return

    test_id = import_scan(
        session,
        cfg,
        product_name=product_name,
        engagement=engagement,
        branch=branch,
        commit=commit,
        file_path=file_path,
        scan_type=scan_type,
        vuln_label=vuln_label,
        component_label=component_label,
    )
    if test_id is None:
        return

    if not cfg.jira_ready:
        warn(
            "Jira env vars not set; skipping per-finding label sync "
            "(import + native DefectDojo->Jira push still happened)"
        )
        return

    labels = [f"vuln:{vuln_label}", f"component:{component_label}"]
    finding_ids = list_findings_for_test(session, cfg, test_id)
    if not finding_ids:
        log(f"no findings to label for test {test_id}")
        return

    log(f"labelling {len(finding_ids)} finding(s) from test {test_id}")
    labelled = set()
    for finding_id in finding_ids:
        issue_key = wait_for_jira_key(session, cfg, finding_id)
        if not issue_key:
            continue
        # An import can map several findings to the same dedup'd Jira issue;
        # only patch each issue once.
        if issue_key in labelled:
            continue
        if add_jira_labels(cfg, issue_key, labels):
            labelled.add(issue_key)


def build_session(cfg: Config) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Token {cfg.dojo_token}",
            "Accept": "application/json",
        }
    )
    return session


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import scan reports into DefectDojo and add dynamic "
        "per-finding Jira labels (vuln:/component:)."
    )
    parser.add_argument("--product-name", required=True, help="DefectDojo product name")
    parser.add_argument(
        "--engagement", required=True, help="Engagement name (auto-created if absent)"
    )
    parser.add_argument("--branch", required=True, help="Source branch (tagged on import)")
    parser.add_argument("--commit", default="", help="Commit SHA (tagged on import)")
    parser.add_argument(
        "--scan",
        action="append",
        default=[],
        metavar="file:scan_type:vuln_label:component_label",
        help="Repeatable scan tuple. May also be newline-separated for CI inputs.",
    )
    return parser.parse_args(argv)


def expand_scan_args(raw_scans: list[str]) -> list[str]:
    """Allow each --scan value to itself be a multiline blob (CI convenience)."""
    expanded: list[str] = []
    for chunk in raw_scans:
        for line in chunk.splitlines():
            line = line.strip()
            if line:
                expanded.append(line)
    return expanded


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    cfg = Config()

    if not cfg.dojo_ready:
        warn(
            "DEFECTDOJO_URL / DEFECTDOJO_API_TOKEN not set; nothing uploaded. "
            "Exiting 0 so the build is not affected."
        )
        return 0

    scans = expand_scan_args(args.scan)
    if not scans:
        warn("no --scan tuples provided; nothing to do")
        return 0

    session = build_session(cfg)
    log(
        f"product='{args.product_name}' engagement='{args.engagement}' "
        f"branch='{args.branch}' commit='{args.commit[:12]}' scans={len(scans)}"
    )

    for raw in scans:
        parsed = parse_scan_tuple(raw)
        if parsed is None:
            continue
        file_path, scan_type, vuln_label, component_label = parsed
        try:
            process_scan(
                session,
                cfg,
                product_name=args.product_name,
                engagement=args.engagement,
                branch=args.branch,
                commit=args.commit,
                file_path=file_path,
                scan_type=scan_type,
                vuln_label=vuln_label,
                component_label=component_label,
            )
        except Exception as exc:  # noqa: BLE001 - never fail the build
            warn(f"unexpected error processing '{raw}': {exc}")

    log("done")
    return 0


if __name__ == "__main__":
    # Belt-and-braces: even an unhandled error must not break the pipeline.
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001
        warn(f"fatal error (ignored to protect the build): {exc}")
        sys.exit(0)
