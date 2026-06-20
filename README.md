# Lybica Security Scan — GitHub Action

One Action that runs Lybica's security scanners as **Lybica-labelled stages**
(`Lybica / SAST`, `Lybica / Secrets`, `Lybica / SBOM`, `Lybica / SCA`,
`Lybica / IaC`, `Lybica / DAST`) and ships findings to **DefectDojo → SVM Jira**.

Scanners live in **`scanners.yaml` — the plugin contract**. Adding a scanner is a
registry edit, not a code change (ADR-11: open/pluggable). The GitHub App installs
a *minimal* caller workflow that just invokes this Action, so Lybica controls the
tools + versions centrally.

## Usage (caller workflow the App installs)
```yaml
jobs:
  lybica:
    runs-on: ubuntu-latest
    env:
      DEFECTDOJO_URL: https://app.lybica.com          # public DefectDojo
      DEFECTDOJO_API_TOKEN: ${{ secrets.DEFECTDOJO_API_TOKEN }}   # per-tenant token
      JIRA_URL: ${{ vars.JIRA_URL }}
      JIRA_USER: ${{ secrets.JIRA_USER }}
      JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - uses: teomach/lybica-action@v1        # public Action repo (productized)
        with:
          product: "Customer Staging"
          engagement: "CI Scans - develop"
          component: backend
          # dast-target: https://staging.example.com   # optional, enables DAST
          # scanners: sast,secrets                       # optional subset
```

## The plugin contract (`scanners.yaml`)
Each scanner is one entry:
```yaml
- name: sast
  stage: "Lybica / SAST"
  kind: code            # code -> scans {target} path; dast -> scans {dast-target} URL
  enabled: true
  install: "pip install semgrep"
  run: "semgrep scan --config auto --json --output {report} {target} || true"
  report: semgrep.json
  scan_type: "Semgrep JSON Report"   # a real DefectDojo parser
  vuln: sast                          # Jira vuln: label
```
`{target}` and `{report}` are substituted at run time. A scanner that errors or
produces no report is skipped — it never fails the build.

## Notes
- Findings POST directly to the public DefectDojo (`DEFECTDOJO_URL`, e.g.
  `https://app.lybica.com`) over the internet — no Tailscale needed.
- Engine = the vendored `dojo_upload.py` (import-scan + push-to-Jira + per-finding
  vuln/component labels + secret redaction).
- This is the teomach-internal source of truth; the **public** `teomach/lybica-action`
  is a mirror so external customer workflows can `uses:` it.
