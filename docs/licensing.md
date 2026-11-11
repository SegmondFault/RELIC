# Licensing assertions

RELIC records licensing as evidence-backed assertions rather than as a mutable
field on a Binary. A claim targets exactly one `source` or `binary_record` and
uses an SPDX license expression. This supports single licences, alternatives,
combined obligations, exceptions and local `LicenseRef-*` identifiers without
changing the Binary schema.

An absent assertion means **not assessed**. `NOASSERTION` records an explicit
decision not to make a licensing assertion. `NONE` records that the inspected
material contained no licensing information; it does not prove that the work
has no copyright or licence obligations.

## Evidence and uncertainty

Each assertion records one basis:

- `declared`: stated by the upstream author or distributor;
- `detected`: reported by a scanner or other deterministic tool;
- `inferred`: inferred from indirect evidence;
- `analyst_assessed`: concluded by an analyst after review.

Confidence is optional. Supporting cell-seal JSON may be linked through
`evidence_provenance_id`; scanner name/version, SPDX License List version,
matched notices and source-code references belong in that evidence rather than
in fixed relational columns.

A Source assertion is not silently copied onto its Binaries. Queries may show
it as inherited context, while a Binary-specific assertion remains a separate
claim. This keeps the distinction between known source licensing and the
contents of a produced or acquired Binary visible.

## Integrity boundary

Licence assertions are independently analyst-signed because they may be added
after the Binary's original signed Batch. The application must validate the
SPDX expression and verify the canonical assertion signature before one atomic
database transaction inserts the assertion. The database enforces the analyst
role, target existence, confidence range and exactly-one-target rule.

Assertions are corrected by appending a replacement and revoking the obsolete
assertion. Existing Sources, Binaries, Batches and signatures are never
rewritten or backfilled by migration 005.
