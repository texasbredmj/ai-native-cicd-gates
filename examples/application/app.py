"""Small deterministic application under test, not part of the gate implementation."""

import argparse
import json
import time
from pathlib import Path


def fault():
    return json.loads(Path(__file__).with_name("settings.json").read_text())["fault"]


def add(a, b):
    return a - b if fault() == "unit" else a + b


def run(case):
    result = {
        "case_id": case,
        "state": "SUCCEEDED",
        "value": 0,
        "attempts": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "claimed_verified": True,
    }
    tool = "math.add" if case == "sum" else "inventory.read"
    args = {"a": 7, "b": 5} if case == "sum" else {"sku": "demo-kit"}
    mode = fault()
    if mode == "policy" and case == "stock":
        tool, args = "shell.exec", {}
    result["tool_calls"] = []
    inventory = {"demo-kit": 7}
    for attempt in range(1, 4):
        result["attempts"] = attempt
        result["tool_calls"].append({"name": tool, "arguments": args})
        if tool not in {"math.add", "inventory.read"}:
            result["state"] = "FAILED"
            break
        if case == "recovery" and attempt < 3:
            continue  # The fixture dependency fails before the first two reads.
        result["value"] = (
            add(args["a"], args["b"]) if tool == "math.add" else inventory[args["sku"]]
        )
        break
    if mode == "integration" and case == "sum":
        result["state"] = "FAILED"
    if mode in {"completion", "regression"} and case == "stock":
        result["value"] = 999
    if mode == "schema" and case == "stock":
        result["input_tokens"] = "unknown"
    if mode == "latency" and case == "stock":
        time.sleep(6)
    if mode == "cost" and case == "stock":
        result["input_tokens"] = 1000
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=["sum", "stock", "recovery"], required=True)
    print(json.dumps(run(parser.parse_args().case)))
