"""Explicit network operation: capture a real pip-audit/PyPI advisory snapshot."""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--target", type=Path, required=True)
args = parser.parse_args()
target = args.target.resolve()
lock = target / "requirements.lock"
destination = target / "security"
destination.mkdir(exist_ok=True)
result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(lock),
        "--no-deps",
        "--disable-pip",
        "--format",
        "json",
        "--progress-spinner",
        "off",
    ],
    capture_output=True,
    text=True,
    timeout=180,
)
if result.returncode not in {0, 1}:
    raise RuntimeError("pip-audit could not complete; snapshot was not replaced")
report = json.loads(result.stdout)
value = {
    "schema_version": 1,
    "tool": "pip-audit",
    "tool_version": version("pip-audit"),
    "advisory_source": "https://pypi.org",
    "audited_at": datetime.now(UTC).isoformat(),
    "requirements_sha256": hashlib.sha256(lock.read_text(encoding="utf-8").encode()).hexdigest(),
    "report": report,
}
(destination / "dependencies.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
print(
    json.dumps(
        {
            "snapshot_written": True,
            "dependencies": len(report["dependencies"]),
            "vulnerabilities": sum(len(d["vulns"]) for d in report["dependencies"]),
        }
    )
)
raise SystemExit(result.returncode)
