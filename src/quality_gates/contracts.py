import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Call(Strict):
    name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, int | str]


class Result(Strict):
    case_id: str = Field(pattern=r"^[a-z0-9-]{1,40}$")
    state: Literal["SUCCEEDED", "FAILED"]
    value: int
    attempts: int = Field(ge=1, le=3)
    tool_calls: list[Call] = Field(max_length=3)
    input_tokens: int = Field(ge=0, le=100000)
    output_tokens: int = Field(ge=0, le=100000)
    claimed_verified: bool


class Case(Strict):
    id: str = Field(pattern=r"^[a-z0-9-]{1,40}$")
    expected_value: int
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, int | str]
    attempts: int = Field(ge=1, le=3)


class Policy(Strict):
    version: str = Field(min_length=1, max_length=64)
    max_case_latency_ms: int = Field(ge=1, le=30000)
    max_case_cost_nusd: int = Field(ge=0, le=100000000)
    input_nusd_per_token: int = Field(ge=0, le=100000)
    output_nusd_per_token: int = Field(ge=0, le=100000)
    min_completion_rate: float = Field(ge=0, le=1, allow_inf_nan=False)
    max_policy_violations: int = Field(ge=0, le=100)
    audit_max_age_days: int = Field(ge=1, le=90)
    cases: list[Case] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique(self):
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate case IDs")
        return self


def read_json(path: Path, limit=2 * 1024 * 1024):
    if path.stat().st_size > limit:
        raise ValueError("JSON input exceeds size budget")

    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate JSON object key")
            result[k] = v
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def text_hash(path):
    return hashlib.sha256(path.read_text(encoding="utf-8").encode()).hexdigest()


def inside(root: Path, relative: str):
    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()) or (root / relative).is_symlink():
        raise ValueError("input path escapes the target root")
    return target
