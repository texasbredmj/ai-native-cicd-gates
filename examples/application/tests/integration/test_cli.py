import json
import subprocess
import sys


def test_cli():
    result = subprocess.run(
        [sys.executable, "app.py", "--case", "sum"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    data = json.loads(result.stdout)
    assert data["state"] == "SUCCEEDED" and data["value"] == 12
