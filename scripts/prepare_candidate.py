"""Copy the known fixture and introduce one explicit deterministic regression."""

import argparse
import json
import secrets
import shutil
import string
from pathlib import Path

MUTATIONS = {
    "unit": "unit_tests",
    "integration": "integration_tests",
    "schema": "schema_validation",
    "dependency": "dependency_security",
    "secret": "secret_scan",
    "container": "container_build",
    "regression": "evaluation_regression",
    "completion": "task_completion",
    "latency": "latency",
    "cost": "cost",
    "policy": "policy_violations",
}


def prepare(source: Path, target: Path, mutation: str):
    if mutation not in {*MUTATIONS, "none"}:
        raise ValueError("unknown mutation")
    if target.exists():
        raise ValueError("candidate copy must be new")
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    mode = mutation if mutation not in {"dependency", "secret", "container", "none"} else "none"
    (target / "settings.json").write_text(json.dumps({"fault": mode}), encoding="utf-8")
    if mutation == "dependency":
        p = target / "security/dependencies.json"
        value = json.loads(p.read_text(encoding="utf-8"))
        value["report"]["dependencies"][0]["vulns"].append(
            {
                "id": "TEST-DEPENDENCY-001",
                "fix_versions": [],
                "description": "Synthetic regression fixture, not a real advisory",
            }
        )
        p.write_text(json.dumps(value, indent=2), encoding="utf-8")
    elif mutation == "secret":
        # Random synthetic token, never issued by or sent to any service.
        fake = (
            "gh"
            + "p_"
            + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
        )
        (target / "leaked-key.txt").write_text("token=" + fake, encoding="utf-8")
    elif mutation == "container":
        p = target / "Dockerfile"
        p.write_text(p.read_text(encoding="utf-8") + "\nRUN false\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source", type=Path, default=Path(__file__).resolve().parents[1] / "examples/application"
    )
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--mutation", choices=["none", *MUTATIONS], required=True)
    args = parser.parse_args()
    prepare(args.source, args.target, args.mutation)
