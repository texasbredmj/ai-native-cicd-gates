import json
from datetime import UTC, datetime
from pathlib import Path

from quality_gates.security import check_dependencies

root = Path(__file__).resolve().parents[1]
report = check_dependencies(
    root / "requirements.lock", root / "security/dependencies.json", datetime.now(UTC).date(), 30
)
assert not report["vulnerabilities"]
print(json.dumps(report))
