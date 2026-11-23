# Behavioural compositions

Maliciousness does not always belong to an individual Function or Binary. A
loader, decoder and network routine may each be neutral in isolation while
their ordered combination implements malicious behaviour.

RELIC therefore keeps the existing signed `classification` assertion and adds
an optional target representing the combination:

| Table | Meaning |
| --- | --- |
| `behavioural_composition` | Analyst-defined composition metadata and signature. |
| `composition_member` | Exact Binary or Function members, their role, and optional order. |
| `classification` | Signed label, confidence and evidence targeting the composition. |

`composition_member.target_type` is deliberately restricted to `binary` and
`function`. A BSim, provenance object or Batch is evidence or packaging, not
itself executable behaviour.

`member_role` records why a member matters, for example `loader`, `decoder`,
`payload`, `persistence` or `c2`. `sequence_number` starts at zero when order is
asserted and remains `NULL` for an unordered set.

## Admission and correction

`POST /v1/behavioural-compositions` writes the composition and all its members
in one transaction. The Analyst signs the composition together with every
member (format in [`authentication.md`](authentication.md#behavioural-composition)),
and the row states its `member_count`: the database refuses a member beyond
that count and, when the transaction commits, a composition with fewer. A
committed composition can therefore never gain or lose a member, and the
stored membership is always the signed one (`relic-verify` re-checks it).
It is then classified like any other target, through `POST
/v1/classifications`. Composition metadata and membership rows are immutable.

A correction or changed member set creates a new composition and signed
classification; the analyst then uses the ordinary revocation workflow for the
superseded classification or composition. A composition classification never
propagates automatically to its member Functions or Binaries.

This remains optional. Existing Functions, Binaries and classifications need
no migration or backfill.
