import json
import os
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, date, datetime
from importlib.resources import files
from pathlib import Path

from .contracts import Policy, Result, digest, inside, read_json, text_hash
from .security import check_dependencies, scan_secrets
from .telemetry import provider

GITLEAKS_IMAGE = (
    "zricethezav/gitleaks@sha256:e1b35e12a8c6fa8901f060459cfb6b2fc4c484d3afbe3b029733a3bbfab07055"
)
REQUIRED = (
    "unit_tests",
    "integration_tests",
    "schema_validation",
    "dependency_security",
    "secret_scan",
    "gitleaks_scan",
    "container_build",
    "evaluation_regression",
    "task_completion",
    "latency",
    "cost",
    "policy_violations",
)


def command(args, cwd, timeout=30):
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    started = time.perf_counter()
    result = subprocess.run(
        args, cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False
    )
    if len(result.stdout) + len(result.stderr) > 2 * 1024 * 1024:
        raise ValueError("command output exceeds budget")
    return result, (time.perf_counter() - started) * 1000


def pytest_gate(target, output, kind):
    xml = output / (kind + ".xml")
    result, elapsed = command(
        [
            sys.executable,
            "-m",
            "pytest",
            str(inside(target, "tests/" + kind)),
            "-q",
            "-p",
            "no:cacheprovider",
            "--junitxml=" + str(xml),
        ],
        target,
    )
    if not xml.exists():
        raise ValueError("pytest did not emit JUnit evidence")
    suites = list(ET.parse(xml).getroot().iter("testsuite"))
    counts = {
        k: sum(int(s.get(k, 0)) for s in suites) for k in ["tests", "failures", "errors", "skipped"]
    }
    passed = (
        result.returncode == 0
        and counts["tests"] > 0
        and not any(counts[k] for k in ["failures", "errors", "skipped"])
    )
    return passed, {"junit": counts, "exit_code": result.returncode, "latency_ms": elapsed}


def gitleaks(target, output):
    trusted = Path(str(files("quality_gates"))).resolve()
    result, _ = command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            str(target) + ":/src:ro",
            "--volume",
            str(output) + ":/out",
            "--volume",
            str(trusted) + ":/policy:ro",
            GITLEAKS_IMAGE,
            "dir",
            "/src",
            "--no-banner",
            "--redact",
            "--ignore-gitleaks-allow",
            "--config",
            "/policy/gitleaks.toml",
            "--gitleaks-ignore-path",
            "/policy/empty-ignore",
            "--report-format",
            "json",
            "--report-path",
            "/out/gitleaks.json",
        ],
        target,
        60,
    )
    if result.returncode not in {0, 1} or not (output / "gitleaks.json").exists():
        raise ValueError("Gitleaks failed to execute or emit its report")
    data = read_json(output / "gitleaks.json")
    findings = [
        {"rule": row["RuleID"], "file": row["File"], "line": row["StartLine"]} for row in data
    ]
    return result.returncode == 0 and not findings, {"image": GITLEAKS_IMAGE, "findings": findings}


def container_gate(target):
    image = "ai-gates-candidate:" + uuid.uuid4().hex
    build, _ = command(
        ["docker", "build", "--network=none", "--tag", image, str(target)], target, 90
    )
    if build.returncode:
        return False, {"build_exit_code": build.returncode}
    result, _ = command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--pids-limit",
            "64",
            image,
            "--case",
            "sum",
        ],
        target,
        15,
    )
    valid = False
    if result.returncode == 0:
        parsed = Result.model_validate_json(result.stdout)
        valid = parsed.state == "SUCCEEDED" and parsed.value == 12
    return valid, {
        "build_exit_code": 0,
        "run_exit_code": result.returncode,
        "image": image,
        "network": "none",
        "root_filesystem": "read-only",
    }


def benchmark(target, policy):
    records = []
    for case in policy.cases:
        started = time.perf_counter()
        row = {
            "case_id": case.id,
            "latency_ms": 0.0,
            "schema_valid": False,
            "completed": False,
            "policy_violations": 0,
            "cost_nusd": 0,
            "error": None,
        }
        try:
            result, elapsed = command(
                [sys.executable, str(inside(target, "app.py")), "--case", case.id], target, 10
            )
            row["latency_ms"] = elapsed
            if result.returncode:
                raise ValueError("benchmark process failed")
            value = Result.model_validate_json(result.stdout)
            row["schema_valid"] = True
            row["output"] = value.model_dump()
            row["completed"] = (
                value.case_id == case.id
                and value.state == "SUCCEEDED"
                and value.value == case.expected_value
                and value.attempts == case.attempts
                and len(value.tool_calls) == case.attempts
                and all(
                    c.name == case.tool and c.arguments == case.arguments for c in value.tool_calls
                )
            )
            row["policy_violations"] = sum(
                c.name not in {c.tool for c in policy.cases} for c in value.tool_calls
            )
            row["cost_nusd"] = (
                value.input_tokens * policy.input_nusd_per_token
                + value.output_tokens * policy.output_nusd_per_token
            )
            # Claims are compared with independently calculated acceptance, not trusted.
            row["verification_accurate"] = value.claimed_verified == row["completed"]
        except (ValueError, TypeError, KeyError):
            row["error"] = "invalid benchmark output"
        except subprocess.TimeoutExpired:
            row["error"] = "benchmark timeout"
            row["latency_ms"] = (time.perf_counter() - started) * 1000
        records.append(row)
    return records


def run(
    target: Path,
    output: Path,
    containers=True,
    policy_path: Path | None = None,
    as_of: date | None = None,
):
    target = target.resolve()
    output = output.resolve()
    if any(path.is_symlink() for path in target.rglob("*")):
        raise ValueError("target symlinks are not supported")
    if output.is_relative_to(target):
        raise ValueError("evidence output must be outside the candidate directory")
    for path in [
        "app.py",
        "requirements.lock",
        "security/dependencies.json",
        "baseline.json",
        "Dockerfile",
    ]:
        if not inside(target, path).is_file():
            raise ValueError("missing required candidate file: " + path)
    policy_path = policy_path or Path(str(files("quality_gates").joinpath("policy.json")))
    policy = Policy.model_validate(read_json(policy_path))
    baseline = read_json(inside(target, "baseline.json"))
    suite_hash = digest([c.model_dump() for c in policy.cases])
    output.mkdir(parents=True, exist_ok=False)
    telemetry = provider(output / "traces.jsonl")
    tracer = telemetry.get_tracer("quality_gates", "0.1.0")
    gates = {}
    records = []

    def check(name, operation):
        with tracer.start_as_current_span(name) as span:
            try:
                passed, details = operation()
                state = "PASSED" if passed else "FAILED"
            except (
                ValueError,
                OSError,
                KeyError,
                TypeError,
                subprocess.TimeoutExpired,
                ET.ParseError,
            ) as exc:
                state = "FAILED"
                details = {"error": type(exc).__name__}
            gates[name] = {"state": state, "details": details}
            span.set_attribute("gate.state", state)

    try:
        with tracer.start_as_current_span("quality-gates") as root:
            trace_id = format(root.get_span_context().trace_id, "032x")
            for kind in ["unit", "integration"]:
                check(kind + "_tests", lambda kind=kind: pytest_gate(target, output, kind))
            check(
                "secret_scan",
                lambda: (lambda scan: (not scan["findings"], scan))(scan_secrets(target)),
            )

            def audit():
                value = check_dependencies(
                    inside(target, "requirements.lock"),
                    inside(target, "security/dependencies.json"),
                    as_of or datetime.now(UTC).date(),
                    policy.audit_max_age_days,
                )
                return not value["vulnerabilities"], value

            check("dependency_security", audit)
            if containers:
                check("gitleaks_scan", lambda: gitleaks(target, output))
                check("container_build", lambda: container_gate(target))
            else:
                for name in ["gitleaks_scan", "container_build"]:
                    gates[name] = {
                        "state": "SKIPPED",
                        "details": {"reason": "portable profile; not a full delivery check"},
                    }
            with tracer.start_as_current_span("benchmark"):
                records = benchmark(target, policy)
            complete = sum(r["completed"] for r in records) / len(records)
            schema = all(r["schema_valid"] for r in records)
            violations = sum(r["policy_violations"] for r in records)
            metrics = {
                "completion_rate": complete,
                "policy_violations": violations,
                "max_latency_ms": max(r["latency_ms"] for r in records),
                "max_cost_nusd": max(r["cost_nusd"] for r in records),
            }
            check(
                "schema_validation",
                lambda: (schema, {"valid_cases": sum(r["schema_valid"] for r in records)}),
            )
            check(
                "task_completion",
                lambda: (schema and complete >= policy.min_completion_rate, metrics),
            )
            check(
                "latency",
                lambda: (
                    schema and metrics["max_latency_ms"] <= policy.max_case_latency_ms,
                    {
                        "observed_ms": metrics["max_latency_ms"],
                        "limit_ms": policy.max_case_latency_ms,
                    },
                ),
            )
            check(
                "cost",
                lambda: (
                    schema and metrics["max_cost_nusd"] <= policy.max_case_cost_nusd,
                    {
                        "observed_nusd": metrics["max_cost_nusd"],
                        "limit_nusd": policy.max_case_cost_nusd,
                    },
                ),
            )
            check(
                "policy_violations",
                lambda: (
                    schema and violations <= policy.max_policy_violations,
                    {"violations": violations, "limit": policy.max_policy_violations},
                ),
            )

            def regression():
                if baseline["suite_sha256"] != suite_hash or set(baseline["cases"]) != {
                    c.id for c in policy.cases
                }:
                    raise ValueError("baseline suite/case mismatch")
                if any(type(v) is not bool for v in baseline["cases"].values()):
                    raise ValueError("baseline scores must be booleans")
                regressions = [
                    r["case_id"]
                    for r in records
                    if baseline["cases"][r["case_id"]]
                    and not (r["completed"] and r.get("verification_accurate", False))
                ]
                return schema and not regressions, {
                    "baseline_version": baseline["version"],
                    "regressions": regressions,
                }

            check("evaluation_regression", regression)
    finally:
        telemetry.shutdown()
    if set(gates) != set(REQUIRED):
        raise ValueError("gate set is incomplete")
    state = (
        "FAILED"
        if any(g["state"] == "FAILED" for g in gates.values())
        else ("INCOMPLETE" if any(g["state"] == "SKIPPED" for g in gates.values()) else "PASSED")
    )
    report = {
        "schema_version": 1,
        "run_id": str(uuid.uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "as_of": (as_of or datetime.now(UTC).date()).isoformat(),
        "policy_sha256": text_hash(policy_path),
        "suite_sha256": suite_hash,
        "state": state,
        "gate_passed": state == "PASSED",
        "trace_id": trace_id,
        "gates": gates,
        "benchmark": records,
        "live_model_calls": 0,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "benchmark.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )
    return report
