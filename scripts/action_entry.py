import os
import subprocess
import sys
from pathlib import Path

workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
target = (workspace / os.environ["GATE_TARGET"]).resolve()
output = (workspace / os.environ["GATE_OUTPUT"]).resolve()
if not target.is_relative_to(workspace) or not output.is_relative_to(workspace):
    raise ValueError("action paths must remain within the checked-out workspace")
result = subprocess.run(
    [sys.executable, "-m", "quality_gates.cli", "--target", str(target), "--output", str(output)],
    check=False,
)
raise SystemExit(result.returncode)
