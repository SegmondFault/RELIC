# RELIC Bloom reference experiment

This crate is an isolated, synthetic reference model for decisions recorded in
[`docs/bloom-filters.md`](../../docs/bloom-filters.md). It is not a production
worker, file format, API, database adapter or deployment component.

It exists to validate:

- the standard Bloom sizing formula;
- domain-separated deterministic index generation;
- no false negatives for inserted synthetic values;
- empirical false-positive behavior;
- input-order and duplicate independence;
- a small deterministic payload/golden vector;
- strict corruption/truncation rejection; and
- the canonical manifest digest/signature boundary.

It intentionally does not implement the planned 256-shard container,
PostgreSQL snapshot, MMR verification, content-addressed publication, mmap
consumer or service lifecycle. Those require their later implementation gates
and real-corpus qualification.

Run the ordinary synthetic suite with:

```bash
cargo test -p relic-bloom-reference
```

The ignored three-million-value timing probe is a local diagnostic, not a
portable benchmark or production claim:

```bash
cargo test -p relic-bloom-reference synthetic_three_million_report \
  --release -- --ignored --nocapture
```
