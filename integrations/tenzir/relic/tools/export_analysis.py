"""Publish a successful Parquet analysis with exact pipeline and digest manifest."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def export(pipeline, destination, checkpoint, schema_version, tenzir_args=()):
    pipeline, destination = Path(pipeline).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError("analysis destination already exists")
    if not checkpoint:
        raise ValueError("checkpoint is required")
    code = pipeline.read_bytes()
    # The caller supplies a complete checkpoint-pinned pipeline with the supported sink.
    text = code.decode("utf-8")
    if 'env("RELIC_CHECKPOINT")' not in text or "relic::export_analysis" not in text:
        raise ValueError(
            "pipeline must use RELIC_CHECKPOINT and relic::export_analysis"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".relic-analysis-", dir=destination.parent
    ) as temporary:
        staging = Path(temporary) / "result"
        staging.mkdir()
        output = staging / "data.parquet"
        env = dict(
            os.environ, RELIC_CHECKPOINT=checkpoint, RELIC_ANALYSIS_OUTPUT=str(output)
        )
        version = subprocess.run(
            ["tenzir", *tenzir_args, "version | write_ndjson"],
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        version = json.loads(version.stdout)["version"]
        result = subprocess.run(
            ["tenzir", *tenzir_args, "--parallelism=disabled", text],
            env=env,
            capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(
                "analysis failed; no result published (inspect pipeline in a trusted session)"
            )
        if not output.is_file():
            raise RuntimeError("pipeline did not produce Parquet")
        (staging / "pipeline.tql").write_bytes(code)
        manifest = dict(
            analysis_id=str(uuid.uuid4()),
            relic_checkpoint=checkpoint,
            relic_schema_version=schema_version,
            pipeline="pipeline.tql",
            pipeline_sha256=digest(staging / "pipeline.tql"),
            tenzir_version=version,
            created_at=datetime.now(timezone.utc).isoformat(),
            output="data.parquet",
            output_format="parquet",
            output_sha256=digest(output),
        )
        # JSON is valid YAML 1.2 and avoids a runtime YAML dependency.
        (staging / "manifest.yaml").write_text(json.dumps(manifest, indent=2) + "\n")
        staging.rename(destination)
    return manifest


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pipeline")
    p.add_argument("destination")
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--schema-version", default="relic.function-fact/1.0")
    p.add_argument(
        "--tenzir-arg",
        action="append",
        default=[],
        help="Repeat for --config=, --endpoint=, --package-dirs=; use --tenzir-arg=VALUE",
    )
    a = p.parse_args()
    export(a.pipeline, a.destination, a.checkpoint, a.schema_version, a.tenzir_arg)
    print("Analysis and manifest published.")
