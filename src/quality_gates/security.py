import re
from datetime import date, datetime

from packaging.utils import canonicalize_name

from .contracts import read_json, text_hash

PATTERNS = [
    r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    r"github_pat_[A-Za-z0-9_]{70,255}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"AKIA[A-Z0-9]{16}",
]


def scan_secrets(root):
    findings = []
    files = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlinks are not allowed in scanned targets")
        if not path.is_file() or any(
            part in {".git", "__pycache__", ".pytest_cache", ".venv"}
            for part in path.relative_to(root).parts
        ):
            continue
        files += 1
        if files > 1000 or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("secret scan exceeds file/size budget")
        content = path.read_bytes().decode("utf-8", errors="replace")
        for number, line in enumerate(content.splitlines(), 1):
            if any(re.search(p, line) for p in PATTERNS):
                findings.append(
                    {
                        "file": path.relative_to(root).as_posix(),
                        "line": number,
                        "secret": "REDACTED",
                    }
                )
    return {"files_scanned": files, "findings": findings}


def check_dependencies(lock, snapshot, as_of: date, max_age):
    packages = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9.!+-]+", line):
            raise ValueError("lock must contain fully pinned simple package versions")
        name, version = line.split("==")
        name = canonicalize_name(name)
        if name in packages:
            raise ValueError("duplicate lock package")
        packages[name] = version
    if not packages:
        raise ValueError("empty audited lock is not accepted")
    value = read_json(snapshot)
    if value["tool"] != "pip-audit" or value["requirements_sha256"] != text_hash(lock):
        raise ValueError("audit tool or lock provenance mismatch")
    audited = datetime.fromisoformat(value["audited_at"]).date()
    if not 0 <= (as_of - audited).days <= max_age:
        raise ValueError("dependency audit snapshot is stale or from the future")
    reported = {}
    vulnerabilities = []
    for dependency in value["report"]["dependencies"]:
        name = canonicalize_name(dependency["name"])
        if name in reported or "skip_reason" in dependency:
            raise ValueError("audit contains duplicate or skipped packages")
        reported[name] = dependency["version"]
        vulnerabilities.extend({"package": name, "id": v["id"]} for v in dependency["vulns"])
    if reported != packages:
        raise ValueError("audit does not exactly cover the pinned lock")
    return {
        "packages_audited": len(packages),
        "audited_at": value["audited_at"],
        "vulnerabilities": vulnerabilities,
        "tool_version": value["tool_version"],
    }
