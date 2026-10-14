import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from quality_gates.contracts import Result, inside, read_json
from quality_gates.runner import REQUIRED, run
from quality_gates.security import check_dependencies

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from prepare_candidate import MUTATIONS, prepare  # noqa: E402


def candidate(tmp_path, mutation="none"):
    path = tmp_path / "candidate"
    prepare(ROOT / "examples/application", path, mutation)
    return path


def test_valid_portable_is_incomplete_not_delivery_success(tmp_path):
    result = run(candidate(tmp_path), tmp_path / "out", containers=False)
    assert result["state"] == "INCOMPLETE" and not result["gate_passed"]
    assert set(result["gates"]) == set(REQUIRED)
    assert all(
        g["state"] == "PASSED"
        for k, g in result["gates"].items()
        if k not in {"gitleaks_scan", "container_build"}
    )
    traces = [json.loads(line) for line in (tmp_path / "out/traces.jsonl").read_text().splitlines()]
    assert len({s["trace_id"] for s in traces}) == 1
    assert traces[0]["trace_id"] == result["trace_id"]
    assert any(s["name"] == "benchmark" and s["parent_span_id"] for s in traces)


@pytest.mark.parametrize("mutation", [k for k in MUTATIONS if k not in {"container"}])
def test_regressions_fail_intended_gate(tmp_path, mutation):
    result = run(candidate(tmp_path, mutation), tmp_path / "out", containers=False)
    assert result["state"] == "FAILED" and not result["gate_passed"]
    assert result["gates"][MUTATIONS[mutation]]["state"] == "FAILED"
    if mutation in {"completion", "regression"}:
        stock = next(c for c in result["benchmark"] if c["case_id"] == "stock")
        assert stock["output"]["claimed_verified"] and not stock["completed"]
    if mutation == "secret":
        assert "REDACTED" in json.dumps(result["gates"]["secret_scan"])
        assert "ghp_" not in json.dumps(result)


@pytest.mark.parametrize(
    "update",
    [
        {"input_tokens": True},
        {"input_tokens": -1},
        {"output_tokens": "4"},
        {"attempts": 4},
        {"unknown": "x"},
        {"claimed_verified": "yes"},
    ],
)
def test_result_schema_strict(update):
    data = {
        "case_id": "sum",
        "state": "SUCCEEDED",
        "value": 12,
        "attempts": 1,
        "tool_calls": [],
        "input_tokens": 0,
        "output_tokens": 0,
        "claimed_verified": True,
    }
    data.update(update)
    with pytest.raises(ValidationError):
        Result.model_validate(data)


def test_audit_staleness_lock_binding_and_skipped_dependencies(tmp_path):
    target = candidate(tmp_path)
    path = target / "security/dependencies.json"
    original = read_json(path)
    as_of = datetime.fromisoformat(original["audited_at"]).date()
    check_dependencies(target / "requirements.lock", path, as_of, 30)
    with pytest.raises(ValueError, match="stale"):
        check_dependencies(target / "requirements.lock", path, as_of + timedelta(days=31), 30)
    with pytest.raises(ValueError, match="future"):
        check_dependencies(target / "requirements.lock", path, as_of - timedelta(days=1), 30)
    (target / "requirements.lock").write_text("packaging==1.0\n")
    with pytest.raises(ValueError, match="provenance"):
        check_dependencies(target / "requirements.lock", path, as_of, 30)


@pytest.mark.parametrize(
    "lock",
    [
        "",
        "-r other.txt\n",
        "packaging>=26\n",
        "https://example.com/pkg.whl\n",
        "packaging==26.3\npackaging==26.3\n",
    ],
)
def test_unsafe_or_incomplete_locks_rejected(tmp_path, lock):
    target = candidate(tmp_path)
    (target / "requirements.lock").write_text(lock)
    with pytest.raises(ValueError):
        check_dependencies(
            target / "requirements.lock",
            target / "security/dependencies.json",
            datetime.now(UTC).date(),
            30,
        )


def test_duplicate_json_keys_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"version":1,"version":2}')
    with pytest.raises(ValueError, match="duplicate"):
        read_json(p)


def test_path_escape_and_output_containment(tmp_path):
    target = candidate(tmp_path)
    with pytest.raises(ValueError, match="escapes"):
        inside(target, "../../escape")
    with pytest.raises(ValueError, match="outside"):
        run(target, target / "out", containers=False)


def test_report_directory_not_overwritten(tmp_path):
    target = candidate(tmp_path)
    (tmp_path / "out").mkdir()
    with pytest.raises(FileExistsError):
        run(target, tmp_path / "out", containers=False)


def test_empty_tests_cannot_pass(tmp_path):
    target = candidate(tmp_path)
    (target / "tests/unit/test_math.py").write_text("")
    result = run(target, tmp_path / "out", containers=False)
    assert result["gates"]["unit_tests"]["state"] == "FAILED"


def test_baseline_suite_mismatch_rejected(tmp_path):
    target = candidate(tmp_path)
    p = target / "baseline.json"
    value = read_json(p)
    value["suite_sha256"] = "incorrect"
    p.write_text(json.dumps(value))
    result = run(target, tmp_path / "out", containers=False)
    assert result["gates"]["evaluation_regression"]["state"] == "FAILED"


def test_cli_exit_code_is_nonzero_for_real_regression(tmp_path):
    target = candidate(tmp_path, "completion")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "quality_gates.cli",
            "--target",
            str(target),
            "--output",
            str(tmp_path / "out"),
            "--portable",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["state"] == "FAILED"


def test_live_model_checks_absent_from_required_path():
    assert set(REQUIRED) == {
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
    }


@pytest.mark.containers
@pytest.mark.skipif(os.environ.get("GATES_CONTAINERS") != "1", reason="requires Docker/Gitleaks")
def test_full_required_path(tmp_path):
    result = run(candidate(tmp_path), tmp_path / "out", containers=True)
    assert result["gate_passed"] and result["state"] == "PASSED"
    assert all(g["state"] == "PASSED" for g in result["gates"].values())
