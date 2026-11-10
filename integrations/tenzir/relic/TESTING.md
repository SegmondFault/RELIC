# Verification record

Environment: Linux x86_64; official static Tenzir **6.21.0**,
`tenzir-test 2.3.1`. The downloaded official release archive matched the published
SHA-256 `714806ac62816a106280b4c80bf8e5b39193dce32f1b08e9d0950ac18f127a77`.

Commands run from the package root (with Tenzir binaries on PATH):

- `python -u tests/integration.py`: public readers, examples, Parquet and
  manifest checks passed during development. The official runner below is the
  complete final suite, including additional late-page/shape checks.
- `uvx tenzir-test --update -j 1 --summary`: **2 runner entries passed**;
  assertion baseline reviewed. `integration.py` exercises the real public TQL
  operators against deterministic HTTP fixtures. `live.py` prints
  `SKIP: live API test disabled` and exits successfully; it made no API request.
- `uvx tenzir-test -j 1 --summary`: **2 runner entries passed**, no baseline
  differences and no failures. The live entry remained disabled as above.

From repository root:

- `cargo test --workspace --locked`: **24 unit tests passed**, no failures;
  binary/doc-test targets with zero tests also completed successfully.
- `uvx ruff format integrations/tenzir/relic/tools integrations/tenzir/relic/tests`:
  Python helpers formatted.
- `uvx ruff check --select F integrations/tenzir/relic/tools integrations/tenzir/relic/tests`:
  passed.
- Python AST parsing for all package `.py` files: passed.
- `git diff --check`: passed before staging.

No real RELIC API test was run: the API does not exist yet. No PostgreSQL-backed
atomic-admission SQL tests were run, and no production database was contacted.
Core Rust tests do not substitute for those database tests. All fixture IDs,
hashes, signatures and evidence are synthetic; no cryptographic validity or
scientific conclusion is asserted for them.

Development failures were corrected before the final suite: raw directory
input templating, exact secret configuration, dictionary `items` field access,
Python per-event state lifetime, current `summarize` syntax, package-install
fixture isolation, Python test timeout format and late-page request counts.
The documented staging renderer is still required for the tested installation
path; it is a current limitation, not a claim that source-directory templating
works automatically.

Initial repository inspection found a clean `main` at `ab3d04e`, matching
`origin/main`; `git fetch origin` found no other remote branches and the open-PR
search returned no entries. No applicable repository/ancestor `AGENTS.md` was
present. README and all existing Markdown runbooks were read. `main` was updated
with `git merge --ff-only origin/main` (already current), then
`feature/tql-integration` was created. No core source/schema files were changed.
