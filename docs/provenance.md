# Source and provenance convention

RELIC deliberately keeps **source** and **provenance** separate.

- A `catalogue.source` row records where a submitted object or binary came from.
- A `catalogue.provenance` row stores an inspectable OCSF-style JSON cell seal in
  `object_data` and records how an object or binary was produced and how another
  analyst can inspect or reproduce it. `storage_path` remains nullable for legacy
  or externally retained objects.

This distinction is sufficient to record both artificial analysis builds and
material obtained elsewhere. It does not require another table or mandatory
columns.

## Ecological status

`catalogue.source.is_ecological` is authoritative:

| Value | Meaning |
| --- | --- |
| `TRUE` | Ecological input obtained from a real-world source. |
| `FALSE` | Artificial or synthetic input deliberately produced for analysis. |
| `NULL` | The status is unknown or was not recorded. |

Do not duplicate this value inside the cell seal. If a JSON document contains a
conflicting value, the database column wins.

A source reference is human-readable and need not be a URI. For example, an
artificial build may use `FIDBF-gen local build` as its source name or reference.
An ecological source may instead cite a collection, publication, vendor archive,
or acquisition note.

## OCSF-style cell-seal JSON

New seals use `schema_name = 'ocsf'` and identify the OCSF version in both
`schema_version` and `metadata.version`. RELIC uses the OCSF base-event envelope
and keeps project-specific reproducibility material below `unmapped.relic`.
This makes the object directly inspectable and TQL-friendly without pretending
that build recipes are a new OCSF core event class.

The minimum RELIC contract is:

- an OCSF `class_uid`, `category_uid`, `activity_id`, derived `type_uid`, `time`,
  `severity_id` and `metadata` envelope;
- `metadata.version` naming the OCSF release used by the producer;
- `metadata.product.name = "RELIC"`;
- `unmapped.relic.schema_version = "relic.provenance/1.0"`; and
- the reproducibility recipe and evidence below `unmapped.relic`.

For software/build evidence, prefer the OCSF Software Inventory Info class and
its SBOM/software-component objects when the supplied facts map cleanly. Fields
without a lossless OCSF mapping remain in `unmapped.relic`; do not invent values.

Example:

```json
{
  "class_uid": 5020,
  "category_uid": 5,
  "activity_id": 2,
  "type_uid": 502002,
  "time": 1794900000000,
  "severity_id": 1,
  "metadata": {
    "version": "1.9.0",
    "product": {"name": "RELIC", "vendor_name": "RELIC"}
  },
  "device": {"uid": "analysis-workstation"},
  "unmapped": {
    "relic": {
      "schema_version": "relic.provenance/1.0",
      "origin": {
        "method": "built_locally",
        "machine": "analysis-workstation"
      },
      "source_code": {
        "availability": "available",
        "url": "https://example.org/project/source",
        "revision": "v1.2.3"
      },
      "build": {
        "tool": "fidbf-gen",
        "compiler": "clang 18.1.8",
        "flags": ["-O2"],
        "recipe": "build-release"
      }
    }
  }
}
```

`unmapped.relic.origin.method` may use values such as `built_locally`, `downloaded`, `received`,
or another value defined by the selected schema. Machine labels should be useful
for reproduction without exposing secrets or personal information.

`unmapped.relic.source_code.availability` should be one of `available`, `partial`, `unavailable`,
or `unknown` when that distinction is recorded. `url` and `revision` identify the
code actually used; they are not assertions about authorship or ownership.

For material acquired elsewhere, use the same base envelope and replace its
`unmapped.relic` value with, for example:

```json
"relic": {
  "schema_version": "relic.provenance/1.0",
  "origin": {
    "method": "downloaded",
    "reference": "Malware collection snapshot 2026-10"
  },
  "source_code": {
    "availability": "unknown"
  }
}
```

## Optional and appendable evidence

These JSON fields are optional. Existing records remain valid when they are
absent, and their absence means **not recorded**, not `unavailable` and not
`ecological`.

A later provenance object may add better evidence without rewriting the original
object. It receives its own object bytes, digests, signature, and provenance row.
The original remains inspectable evidence. Relationships such as supersession or
correction may be expressed by the analyst's chosen JSON schema until RELIC has a
demonstrated need for a database-level relationship.

## Examples

Digests are calculated over the agreed canonical JSON serialization, not the
PostgreSQL `jsonb` physical representation. `sha256` is the security digest;
`md5` is retained only for compatibility.

An artificial analysis build made on an analyst machine should normally have:

- `source.is_ecological = FALSE`;
- a source name/reference identifying the local build process;
- a cell seal recording the source-code URL and revision, build recipe, compiler,
  flags, and a non-secret machine label where available.

A binary acquired from elsewhere should normally have:

- `source.is_ecological = TRUE` when it is known to be real-world material, or
  `NULL` when that is genuinely unknown;
- a source reference describing the acquisition;
- a cell seal containing any known source-code link and reproducibility evidence.

The source-code link belongs in the inspectable JSON cell seal. It is optional and
can be added as later evidence; it does not need a dedicated database column.
