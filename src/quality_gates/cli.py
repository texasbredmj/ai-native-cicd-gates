import argparse
import json
from datetime import date
from pathlib import Path

from .runner import run


def main():
    parser = argparse.ArgumentParser(prog="ai-gates")
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--portable", action="store_true")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--as-of", type=date.fromisoformat)
    args = parser.parse_args()
    try:
        report = run(args.target, args.output, not args.portable, args.policy, args.as_of)
        print(
            json.dumps(
                {
                    "state": report["state"],
                    "gate_passed": report["gate_passed"],
                    "report": str(args.output / "report.json"),
                }
            )
        )
        return {"PASSED": 0, "FAILED": 1, "INCOMPLETE": 2}[report["state"]]
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
