# Binaries, libraries and software components

RELIC keeps a **concrete Binary artifact** separate from the **software it is
believed to contain or represent**. This avoids turning a filename, shared
function hash or BSim match into an unsupported identity claim.

The additive model has three tables:

| Table | Meaning |
| --- | --- |
| `software_component` | Immutable normalized identity such as a library, application or runtime. |
| `software_release` | Optional version/source identity for a component. Unknown version or source remains `NULL`. |
| `binary_component_assertion` | Signed analyst claim connecting one Binary to one release. |

An assertion records:

- `relationship`: `build_of`, `statically_contains`, `dynamically_links`,
  `derived_from`, or `other`;
- `basis`: `declared`, `detected`, `inferred`, or `analyst_assessed`;
- optional `confidence` in the inclusive range 0–1;
- optional `evidence_provenance_id` pointing at an inspectable OCSF-style seal;
- analyst identity, creation time, and signature.

No assertion is required. Existing Binaries therefore migrate without a
backfill, and an unknown relationship remains unknown rather than becoming a
guess. Components, releases and assertions are append-only. A correction is a
new signed assertion plus revocation of the superseded assertion.

BSim similarities and FIDBF/function hashes are evidence that may support an
assertion; they do not automatically create one. A shared hash or BSim can
produce several candidate hits, each of which remains disambiguated by its
exact Binary and Function occurrence.

## TQL compatibility

The existing `relic.binary/1.0` event is unchanged. A TQL integration should
export component claims as a separate `relic.binary_component/1.0` event and
join them by `binary_id`. This keeps future analytical pipelines additive and
does not force SQL/API clients to understand component inference.
