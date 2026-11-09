# Source and provenance convention

RELIC deliberately keeps **source** and **provenance** separate.

- A `catalogue.source` row records where a submitted object or binary came from.
- A `catalogue.provenance` row points at an inspectable JSON cell seal that records
  how an object or binary was produced and how another analyst can inspect or
  reproduce it.

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

## Cell-seal JSON

The provenance object uses the schema selected by the submitting analyst through
`schema_name` and `schema_version`. RELIC does not impose one universal JSON
layout. The following fields are a recommended semantic convention when they are
useful:

```json
{
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
```

`origin.method` may use values such as `built_locally`, `downloaded`, `received`,
or another value defined by the selected schema. Machine labels should be useful
for reproduction without exposing secrets or personal information.

`source_code.availability` should be one of `available`, `partial`, `unavailable`,
or `unknown` when that distinction is recorded. `url` and `revision` identify the
code actually used; they are not assertions about authorship or ownership.

For material acquired elsewhere, a minimal cell seal might instead be:

```json
{
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
