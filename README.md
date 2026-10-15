# AI-Native CI/CD Quality Gates

## Start Here

[Launch the complete employer demonstration on GitHub](https://github.com/texasbredmj/ai-engineering-portfolio#start-here).

The public portfolio contains this project's runnable employer source, sample fixtures and verified demonstration, plus one Codespaces launch for all eight projects. No separate private-repository access is required. Run `python scripts/project_demo.py 7` from the portfolio Codespace to demonstrate this project.

The instructions below describe this repository's standalone version. The integrated platform and its current verification evidence are maintained in the portfolio.


Project 07 of AI Systems Engineering Lab: a reusable GitHub composite action and Python CLI
that reject an AI application's release when measured task outcomes regress. A checked-in,
deterministic application makes each gate demonstrable without model credentials or paid calls.

The full profile has twelve required gates. The demo runs a valid candidate and eleven deliberately
broken copies; every broken copy must return exit code 1 and fail its intended gate.

| Gate | Acceptance evidence |
| --- | --- |
| Unit tests | Actual Pytest process, nonempty JUnit, no failures/errors/skips |
| Integration tests | Application subprocess exercised by Pytest; same JUnit requirements |
| Schema validation | Strict Pydantic result contract; unknown fields and coercion rejected |
| Dependency security | Fresh pip-audit snapshot, exact pinned-lock hash and package coverage, zero findings |
| Secret scan | Bounded local pattern scan; findings contain redacted locations |
| Gitleaks scan | Digest-pinned scanner container, trusted rules and ignore file, redacted report |
| Container build | Actual Docker build and successful network-disabled, read-only smoke run |
| Evaluation regression | Reviewed baseline bound to the case-suite hash; outcome and verification accuracy |
| Task completion | Independently compared expected values, states, attempts, tool names and arguments |
| Latency | Runner-measured per-case wall time at most 5 seconds |
| Cost | Validated token counts times policy prices, at most 250,000 nano-USD per case |
| Policy violations | Zero undeclared tool names in validated results |

## Run locally

Use Python 3.11 or later and Docker Desktop/Linux Docker for the full checks. Run from this directory:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.lock .
.venv/Scripts/ai-gates --target examples/application --output .gates/first-run
$env:GATES_CONTAINERS = '1'
.venv/Scripts/python -m pytest -q --junitxml=.gates/tests.xml
.venv/Scripts/python scripts/demo.py
.venv/Scripts/python scripts/check_tool_audit.py
```

On Linux, use `.venv/bin/python` and `.venv/bin/ai-gates`, and set `GATES_CONTAINERS=1`.
Output directories must be new and outside the candidate. Generated copies live in ignored `.work/`;
redacted evidence lives in ignored `.gates/`. The synthetic token fixture is never issued by or sent
to GitHub. Do not upload candidate copies as evidence.

Without Docker, add `--portable` to the CLI and run `pytest -m 'not containers'`.
Portable mode skips Gitleaks and the container check and returns **INCOMPLETE, exit 2** even when
all other gates pass. Full success returns 0; rejected candidates return 1; invalid input returns 2.

The tool itself also has a Dockerfile. `docker build -t ai-native-cicd-gates:local .` installs its wheel
and pinned dependencies as a nonroot user. This image supports portable operation; full checks run
on a Docker-capable host and need the host's Docker client and daemon.

## GitHub Actions

`action.yml` accepts `target-path` and `output-path`, resolved inside `GITHUB_WORKSPACE`, installs
the pinned tool, and propagates the full CLI exit status. The included CI uses `uses: ./` against
`examples/application`. Reuse from another repository by selecting a reviewed, immutable commit
of this repository, with the same two inputs and a Docker-capable runner.

The push/PR workflow has six Windows/Linux × Python 3.11/3.12/3.14 policy jobs and one full Linux
delivery job. The delivery job runs the action, complete harness suite, eleven-mutant demo, and
tool dependency check. It uploads reports, JUnit, JSONL measurements and OpenTelemetry traces
for 14 days, including when checks fail.

`regression-proof.yml` is an explicitly dispatched negative demonstration. Its selected defect
must make the required gate step and workflow **fail**; it has no `continue-on-error` or inverted
exit handling. This expected red run is separate from the green push/PR workflow. Local evidence
is recorded in [verification-summary.json](docs/evidence/verification-summary.json); remote results
are recorded in the portfolio only after publication and inspection.

## Security refresh and scope

Required CI checks committed advisory snapshots offline. Snapshots expire after 30 days, are bound
to the complete lock, and cannot contain skipped packages. Refresh them explicitly with
`python scripts/refresh_audit.py --target .` and `--target examples/application`, review the diff,
and commit it. The manual `refresh-advisories.yml` workflow obtains fresh pip-audit/PyPI results
as an artifact; it does not change the repository. Snapshots do not establish absence of newly
disclosed vulnerabilities between refreshes. The dependency mutation adds an explicitly synthetic
test advisory, while the committed clean snapshots come from actual pip-audit queries.

Tests and candidate Python execute on the runner. This is for reviewed repositories: it is not a
hostile-code sandbox. Policy, baseline, workflows and audit snapshots need normal protected-branch
review. Container restrictions cover the smoke process; they do not isolate host-side tests or
prevent Docker daemon access. Pattern scanners cannot detect every possible secret.

Task outcomes are checked against a three-case fixture oracle. Tool records and token counts are
application outputs, not independent external receipts or billing attestations. The policy fixture
rejects an undeclared tool before executing it; the checker also detects its logged name. The
recovery case really retries two simulated dependency failures before succeeding. Costs are fixture
accounting, and all baseline model token counts and live model calls are zero. No live-model adapter
or paid check is enabled. Adding one requires a separately authorized, opt-in workflow.

See [architecture and verification](docs/architecture.md) for data flow, failure behavior and limits.
