# Lybica scanner image — all OSS scanners pre-installed so CI runs have no
# per-run install overhead. Published public at
# us-docker.pkg.dev/teomach-utils/lybica/lybica-scanner.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
 && pip install --no-cache-dir semgrep checkov requests pyyaml \
 && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh    | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh     | sh -s -- -b /usr/local/bin \
 && rm -rf /var/lib/apt/lists/*

COPY run.py dojo_upload.py scanners.yaml /lybica/
# GitHub mounts the caller repo at /github/workspace and sets it as the workdir.
ENTRYPOINT ["python", "/lybica/run.py"]
