"""Valid candidate must pass; every mutation must exit 1 and fail its intended gate."""

import json
import subprocess
import sys
import uuid
from pathlib import Path

from prepare_candidate import MUTATIONS, prepare

root = Path(__file__).resolve().parents[1]
source = root / "examples/application"
run_id = str(uuid.uuid4())
work = root / ".work" / run_id
output = root / ".gates" / ("demo-" + run_id)
work.mkdir(parents=True)
output.mkdir(parents=True)
results = []
for mutation in ["none", *MUTATIONS]:
    target = work / mutation
    prepare(source, target, mutation)
    directory = output / mutation
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "quality_gates.cli",
            "--target",
            str(target),
            "--output",
            str(directory),
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    expected = 0 if mutation == "none" else 1
    assert result.returncode == expected, (
        mutation,
        result.returncode,
        result.stdout,
        result.stderr[-1500:],
    )
    report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    gate = MUTATIONS.get(mutation)
    if gate:
        assert report["gates"][gate]["state"] == "FAILED", (mutation, report["gates"])
        if mutation == "secret":
            assert report["gates"]["gitleaks_scan"]["state"] == "FAILED"
    else:
        assert report["gate_passed"] and all(
            g["state"] == "PASSED" for g in report["gates"].values()
        )
    results.append(
        {
            "mutation": mutation,
            "exit_code": result.returncode,
            "expected_gate": gate,
            "state": report["state"],
            "intended_failure_detected": bool(gate),
        }
    )
    print(json.dumps(results[-1]), flush=True)
summary = {
    "verified_demo": True,
    "valid_candidate_passed": True,
    "regressions_rejected": len(MUTATIONS),
    "results": results,
    "live_model_calls": 0,
}
(output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print(
    json.dumps(
        {"verified_demo": True, "regressions_rejected": len(MUTATIONS), "evidence": str(output)}
    )
)
