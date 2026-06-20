#!/usr/bin/env python3
"""Lybica CI Action entrypoint.

Runs the registry-defined scanner plugins (scanners.yaml) as Lybica-labelled
GitHub stages, then ships every produced report to DefectDojo -> SVM via the
vendored dojo_upload.py. Adding a scanner is a registry edit, not a code change
(ADR-11: open/pluggable). A scanner failure never fails the build.

Config via env (set by action.yml):
  LYBICA_TARGET      path to scan (code scanners)        default "."
  LYBICA_DAST_TARGET URL to scan (dast scanners)         default "" (skips dast)
  LYBICA_PRODUCT     DefectDojo product                  required
  LYBICA_ENGAGEMENT  DefectDojo engagement               required
  LYBICA_BRANCH / LYBICA_COMMIT                           optional (tagged on import)
  LYBICA_COMPONENT   component: label on findings         default "app"
  LYBICA_SCANNERS    CSV subset of scanner names          default "" (= all enabled)
  LYBICA_REGISTRY    registry path                        default ./scanners.yaml
DefectDojo/Jira creds are read from env by dojo_upload.py.
"""
import os
import sys
import shlex
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def _sh(cmd: str) -> int:
    return subprocess.run(cmd, shell=True).returncode


def _nonempty(path: str) -> bool:
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


def main() -> int:
    import yaml  # provided by the action's pip install

    target = os.environ.get("LYBICA_TARGET", ".")
    dast_target = os.environ.get("LYBICA_DAST_TARGET", "").strip()
    component = os.environ.get("LYBICA_COMPONENT", "app")
    subset = [s.strip() for s in os.environ.get("LYBICA_SCANNERS", "").split(",") if s.strip()]
    registry_path = os.environ.get("LYBICA_REGISTRY", os.path.join(HERE, "scanners.yaml"))

    with open(registry_path) as fh:
        registry = yaml.safe_load(fh) or {}
    scanners = registry.get("scanners", [])

    specs = []
    for sc in scanners:
        name = sc["name"]
        if not sc.get("enabled", True):
            continue
        if subset and name not in subset:
            continue
        kind = sc.get("kind", "code")
        tgt = dast_target if kind == "dast" else target
        if kind == "dast" and not dast_target:
            print(f"[lybica] {name}: no dast-target provided; skipping")
            continue

        stage = sc.get("stage", f"Lybica / {name}")
        report = sc["report"]
        print(f"::group::{stage}")
        try:
            install = sc.get("install")
            if install:
                _sh(install)
            run = sc["run"].format(target=shlex.quote(tgt), report=shlex.quote(report))
            _sh(run)
        except Exception as exc:  # a broken plugin must never fail the build
            print(f"[lybica] scanner {name} error: {exc}")
        finally:
            print("::endgroup::")

        if _nonempty(report):
            specs.append(f"{report}:{sc['scan_type']}:{sc.get('vuln', name)}:{component}")
        else:
            print(f"[lybica] {name}: no/empty report ({report}); skipping")

    if not specs:
        print("[lybica] no reports produced; nothing to upload")
        return 0

    cmd = [
        sys.executable, os.path.join(HERE, "dojo_upload.py"),
        "--product-name", os.environ["LYBICA_PRODUCT"],
        "--engagement", os.environ["LYBICA_ENGAGEMENT"],
        "--branch", os.environ.get("LYBICA_BRANCH", ""),
        "--commit", os.environ.get("LYBICA_COMMIT", ""),
    ]
    for s in specs:
        cmd += ["--scan", s]
    print(f"[lybica] uploading {len(specs)} report(s) to DefectDojo")
    return subprocess.run(cmd).returncode


if __name__ == "__main__":
    sys.exit(main())
