# RELIC Tenzir/TQL integration

Status: later feature, provisional export contract, deterministic fixture coverage.
The ordinary API is not built yet. This package neither implements that API nor
claims a successful live integration. Keep this branch separate until the API
contract is implemented and the gated live tests are run.

PostgreSQL and the ordinary API own authoritative records, identity, signatures,
provenance, integrity, revocation and atomic admission. TQL consumes read-only
HTTP exports for reproducible analysis and data preparation. No database access,
SQL endpoint, authoritative write, re-signing or evidence repair is introduced.

## Runtime and installation

Verified against official Tenzir 6.21.0. Python >=3.10 and the Tenzir Python
operator runtime are required. Tenzir creates the Python operator environment;
first use may download its dependencies. Keep pipeline parallelism disabled:
page-loop and duplicate-ID state belongs to one serial interpreter.

The source manifest defines these non-secret deployment inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `api_endpoint` | `https://relic.invalid` | HTTPS origin, no credentials/path/query/trailing slash |
| `default_page_size` | `500` | Requested page size, 1–10000 |
| `request_timeout` | `30s` | Positive request timeout |
| `maximum_retries` | `3` | Per-request transient retries, 0–10 |

In the tested 6.21.0 CLI, directly loading the source directory leaves input
placeholders in UDO bodies. Use the included renderer before installation; it
validates settings and writes a new staging copy outside this source tree:

```sh
python3 tools/configure.py /tmp/relic-configured --api-endpoint "$RELIC_API_ENDPOINT"
tenzir 'package_add "/tmp/relic-configured"'
```

The destination must not already exist. Additional flags are
`--default-page-size`, `--request-timeout`, `--maximum-retries`. Do not commit the
rendered deployment directory. An installed package can be used through the
node, or load a rendered directory's parent with `--package-dirs`. The source
package has no auto-start pipelines.

Create a managed Tenzir secret named **`RELIC_API_TOKEN`** in the node/platform
secret store. For a local node, use a protected configuration outside Git:
`tenzir.secrets.RELIC_API_TOKEN`. The fixture suite generates a random disposable
secret and writes a mode-0600 temporary config, then removes it. Plain shell
`RELIC_API_TOKEN` is not itself a configured Tenzir secret. The tested local
configuration uses the exact uppercase name. Keep the modern secret model;
do not enable `legacy-secret-model`. The only use of the secret is the
`Authorization: Bearer …` header expression in `from_http`. It never enters an
event, URL, fixture, pipeline source, manifest or diagnostic header.

HTTPS uses normal certificate verification. HTTP is available only in the test
renderer for loopback fixtures. Missing secrets and rejected authentication
fail the pipeline; permanent HTTP failures are not retried. Tenzir retries
transport failures, 429 and 5xx with bounded exponential backoff. No sensitive
headers are included in package diagnostics.

## Public operators

All readers require a nonempty `checkpoint: string` and emit one independent
analytical event per entity. IDs and nullable foreign keys are preserved.

| Operator | Granularity | Provisional schema version |
| --- | --- | --- |
| `relic::functions` | function occurrence | `relic.function-fact/1.0` |
| `relic::binaries` | binary | `relic.binary/1.0` |
| `relic::bsim_memberships` | function/BSim association | `relic.bsim-membership/1.0` |
| `relic::classifications` | classification assertion | `relic.classification/1.0` |
| `relic::seals` | stored provenance seal | `relic.seal/1.0` |
| `relic::integrity` | integrity entry | `relic.integrity/1.0` |
| `relic::export_analysis` | Parquet sink, required `output: string` | derived output |

Each reader also accepts `cursor: string = null`, `page_size: int = null`,
`include_revoked: bool = false`, `source_id`, `batch_id`, `binary_id`,
`classification` (nullable strings), `is_ecological: bool = null`, and
`created_after`, `created_before` (nullable times). Defaults mean no filter;
`is_ecological=false` selects artificial records while a null filter includes
all three statuses. Date bounds are inclusive lower/exclusive upper. These
filters run locally, after envelope validation, until the future API supports
server-side projections/filtering. A field used by a filter must exist on that
stream; use only meaningful filters for that entity. No implicit joins occur.

```tql
relic::functions checkpoint="chosen-immutable-checkpoint", page_size=500,
  include_revoked=true
select id, binary_id, fidbf_id, bsim_id, revoked
```

## Provisional HTTP contract

GET `/v1/export/functions`, `/binaries`, `/bsim-memberships`, `/classifications`,
`/seals`, `/integrity` (each beneath `/v1/export`). Requests include URL-encoded
`checkpoint`, `limit`, and optional opaque `cursor`. A response is **one JSON
object**, not NDJSON or a JSON array:

```json
{"schema_version":"relic.function-fact/1.0","checkpoint":"chosen-immutable-checkpoint","items":[],"next_url":null}
```

Every item has a nonempty stable string `id` and an explicit boolean `revoked`.
Other fields and relationships are illustrated in `tests/inputs/`. Nullable
FIDBF, BSim, confidence, source status and provenance remain null. The contract
requires occurrence-granularity metadata on function facts (compiler,
architecture, hashes, source status and provenance link) so examples need no
multiplying joins. These are API export projections, not new database columns.

`next_url` must be null or an absolute URL on the same origin and export path,
retaining exactly one unchanged checkpoint and one nonempty cursor. This
stricter provisional contract prevents forwarding credentials to another host.
The API must preserve the selected limit and population in its cursor. All
pages are read, including empty intermediate pages. Schema/checkpoint changes,
missing envelope keys, malformed items, repeated links and duplicate item IDs
fail clearly. Page validation precedes following its link. Duplicate checking
runs in the serial downstream stream and cancels further pagination on failure.
A failed streaming query may already have emitted earlier rows: discard partial
results. Use the manifest publisher for a completed export.

The API team must define snapshot/retention semantics and ensure a checkpoint
pins **all** streams, not just integrity rows. A future MMR checkpoint alone
does not establish a query snapshot. Route/schema adaptations belong in
`operators/internal/`, keeping public calls stable. No real API contract was
available when this package was developed.

## OCSF and signed seals

The repository does not mandate an OCSF release; `schema_name` and
`schema_version` are analyst-selected (see the main provenance documentation).
The synthetic OCSF-like fixture declares 1.6.0; this is not a claim that RELIC has
adopted that version or that the fixture has valid cryptographic authority.
`seal` stays structured JSON, including unknown extension fields. `read_json
raw=true` prevents automatic conversion of strings into timestamps or IPs.
`seal_bytes_base64` preserves the exact original object bytes separately; the
API must supply them along with stored digest, signature, schema name/version.
Never serialize the structured view to verify the original signature.

The reader adds diagnostics **outside** the seal for malformed standard
metadata/file/hash/actor/process/record-integrity container fields.
`custom_extension_validated=false` explicitly states that RELIC extensions
were not validated. Missing optional fields are not invented. These are useful
shape diagnostics, not OCSF conformance, digest or signature verification.
Admission and exact-schema/custom-extension validation remain API duties. The
package never canonicalizes, mutates, hashes again as authority, or re-signs a
signed seal. Revoked evidence remains inspectable with `include_revoked=true`.

## Examples and reproducible Parquet

Set `RELIC_CHECKPOINT` to a retained immutable snapshot. `examples/` contains
commented pipelines for compiler/architecture distribution, three-valued source
status, separate full/specific hash reuse, BSim fanout, classification confidence,
missing provenance, and ML-ready Parquet. Each states population, exclusions,
null handling and grouping. Grouping/deduplication can use substantial memory;
no scientific conclusions follow from fixture data. Compiler/architecture counts
are function-weighted, not binary-weighted. Missing provenance links are only
missing links, not evidence that a signature is invalid.

`export_ml_dataset.tql` retains IDs for group-aware training splits. It excludes
revoked functions by default, keeps absent relationships null and does not
invent classification labels. Its sink reads `RELIC_ANALYSIS_OUTPUT`.
For a completed artifact and manifest, from the configured package directory:

```sh
python3 tools/export_analysis.py examples/export_ml_dataset.tql analysis-output/run-1 \
  --checkpoint "$RELIC_CHECKPOINT" \
  --tenzir-arg=--package-dirs=/path/to/rendered/packages
```

Supply `--tenzir-arg=--config=/protected/tenzir.yaml` and/or `--endpoint=…` as
needed for your environment. These paths/settings must not contain credentials.
The publisher uses a sibling staging directory, requires successful Tenzir
completion, copies the **exact pipeline bytes**, computes streaming SHA-256
hashes and atomically publishes a new directory containing `data.parquet`,
`pipeline.tql`, `manifest.yaml`. It refuses to overwrite an existing result.
The JSON-formatted manifest is valid YAML 1.2 and contains `analysis_id`,
`relic_checkpoint`, `relic_schema_version`, `pipeline`, `pipeline_sha256`,
`tenzir_version`, `created_at`, `output`, `output_format`, `output_sha256`.
For custom pipelines the author must ensure every source uses the supplied
checkpoint and declare the appropriate schema version with `--schema-version`.
External package UDO versions are not bundled: retain the integration Git commit
with the analysis environment. The publisher cannot prove an arbitrary custom
pipeline honored its declared population.

## Tests and limitations

From this package root, with `tenzir`, `tenzir-node`, Python and `uv` on PATH:

```sh
uvx tenzir-test --passthrough -j 1 tests/integration.py
uvx tenzir-test -j 1
```

The official framework's Python runner creates an isolated loopback HTTP fixture
server and temporary node, renders settings and executes the **public TQL**
operators and all examples. Fixtures contain no real credentials or identities.
The suite checks package installation/loading, multiple pages with an empty
middle page, exact record/null/custom-seal preservation, revoked visibility,
empty results, transient retry, permanent/auth failures, loop/duplicate detection,
checkpoint/schema/envelope/origin failures, Parquet roundtrip and export hashes.
Baselines record deterministic assertion summaries rather than temporary paths.
`tests/live.py` is disabled by default. After the real API is built, configure
and install this package and its secret, then run:

```sh
RELIC_LIVE_TEST=1 RELIC_CHECKPOINT="$RELIC_CHECKPOINT" uvx tenzir-test --passthrough tests/live.py
```

The live test reads the complete function stream; no write requests. It does
not validate other live streams or cryptographic evidence. No live test has
been run against a real RELIC API. A skipped test is not a live success.

Known costs: page envelopes are parsed one page at a time; no corpus-sized
record buffer is built, but duplicate IDs/links require O(records + pages)
identifier state. Python page checks launch per-response subprocesses in this
runtime; this prioritizes correctness and needs performance profiling on real
workloads. Keep parallelism disabled. Local filtering does not reduce network
traffic. The renderer workaround, API snapshot semantics, token provisioning,
OCSF schema selection and live compatibility must be reviewed before merge.

Official references checked during implementation:
[packages](https://tenzir.com/docs/guides/packages/create-a-package/),
[typed operators](https://tenzir.com/docs/guides/packages/add-operators/),
[inputs](https://tenzir.com/docs/guides/packages/configure-inputs/),
[HTTP/retries/pagination](https://tenzir.com/docs/reference/operators/from_http/),
[raw JSON](https://tenzir.com/docs/reference/operators/read_json/),
[secrets](https://tenzir.com/docs/explanations/secrets/),
[package tests](https://tenzir.com/docs/guides/packages/test-packages/).
