# timeout: 300
"""Official tenzir-test Python runner; real public TQL operators over local HTTP."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("configure", ROOT / "tools/configure.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixtures = {
    f.stem: json.loads(f.read_text()) for f in (ROOT / "tests/inputs").glob("*.json")
}
token = secrets.token_urlsafe(32)
mode = "normal"
requests = []
attempts = 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        global attempts
        parsed = urlsplit(self.path)
        name = parsed.path.rsplit("/", 1)[-1].replace("-", "_")
        query = parse_qs(parsed.query)
        cursor = query.get("cursor", [None])[0]
        requests.append((name, cursor))
        attempts += 1
        status = 200
        if self.headers.get("Authorization") != "Bearer " + token or mode == "auth":
            status = 401
        if mode == "transient" and attempts == 1:
            status = 503
        if mode == "permanent":
            status = 400
        if status != 200:
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"{}")
            return
        pages = copy.deepcopy(fixtures[name])
        index = {None: 0, "page-2": 1, "page-3": 2}[cursor]
        page = pages[index]
        if page["next_url"]:
            page["next_url"] = page["next_url"].replace("http://127.0.0.1:1", origin)
        if mode == "empty":
            page["items"] = []
            page["next_url"] = None
        if mode == "late_checkpoint" and index == 2:
            page["checkpoint"] = "different"
        if mode == "late_schema" and index == 2:
            page["schema_version"] = "unsupported/9"
        if mode == "checkpoint":
            page["checkpoint"] = "different"
        if mode == "schema":
            page["schema_version"] = "unsupported/9"
        if mode == "malformed":
            del page["next_url"]
        if mode == "items":
            page["items"] = {}
        if mode == "seal_malformed" and page["items"]:
            page["items"][0]["seal"]["file"]["hashes"] = "bad"
        if mode == "loop":
            page["next_url"] = (
                origin
                + parsed.path
                + "?checkpoint=fixture-checkpoint&cursor=page-2&limit=1"
            )
        if mode == "duplicate" and index == 2:
            page["items"] = pages[0]["items"]
        if mode == "origin":
            page["next_url"] = (
                "https://untrusted.invalid/v1/export/functions?checkpoint=fixture-checkpoint&cursor=x"
            )
        if mode == "link_checkpoint" and page["next_url"]:
            page["next_url"] = page["next_url"].replace("fixture-checkpoint", "changed")
        body = json.dumps(page).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
origin = f"http://127.0.0.1:{server.server_port}"
threading.Thread(target=server.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory(prefix="relic-test-") as tmp:
    tmp = Path(tmp)
    package = mod.configure(
        ROOT, tmp / "packages/relic", origin, 1, "5s", 1, fixture=True
    )
    env = dict(
        os.environ,
        TENZIR_SECRETS__RELIC_API_TOKEN=token,
        RELIC_CHECKPOINT="fixture-checkpoint",
        RELIC_ANALYSIS_OUTPUT=str(tmp / "analysis.parquet"),
    )
    env.pop("TENZIR_PACKAGE_DIRS", None)
    endpoint = tmp / "endpoint"
    config = tmp / "tenzir.yaml"
    config.write_text("tenzir:\n  secrets:\n    RELIC_API_TOKEN: " + token + "\n")
    config.chmod(0o600)
    node = subprocess.Popen(
        [
            "tenzir-node",
            f"--config={config}",
            "--endpoint=127.0.0.1:0",
            f"--write-endpoint={endpoint}",
            f"--state-directory={tmp}/state",
            f"--cache-directory={tmp}/cache",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if endpoint.exists():
                break
            if node.poll() is not None:
                raise RuntimeError("temporary node failed")
            time.sleep(0.1)
        ep = endpoint.read_text().strip()

        def run(pipeline, ok=True, load_package=True):
            result = subprocess.run(
                [
                    "tenzir",
                    f"--config={config}",
                    f"--endpoint={ep}",
                    *([f"--package-dirs={tmp}/packages"] if load_package else []),
                    "--parallelism=disabled",
                    "--console-verbosity=quiet",
                    pipeline,
                ],
                env=env,
                text=True,
                capture_output=True,
                timeout=35,
            )
            if token in result.stdout + result.stderr:
                raise AssertionError("secret leaked")
            if ok and result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            if not ok and not result.returncode:
                raise AssertionError(
                    "expected pipeline rejection: "
                    + pipeline
                    + "\n"
                    + result.stdout
                    + result.stderr
                )
            return result

        installed = run(f'package_add "{package}"', load_package=False)
        assert "error:" not in installed.stderr, installed.stderr
        print("Official package_add and operator loading: PASS")
        for name, pages in sorted(fixtures.items()):
            requests.clear()
            r = run(
                f'relic::{name} checkpoint="fixture-checkpoint", include_revoked=true | write_ndjson'
            )
            rows = [json.loads(x) for x in r.stdout.splitlines() if x.strip()]
            expected = [dict(item) for page in pages for item in page["items"]]
            if name == "seals":
                for item in expected:
                    item.update(seal_diagnostics=[], custom_extension_validated=False)
            assert rows == expected, (name, rows)
            assert len(requests) == 3, (name, requests)
            print(name + ": pagination, empty intermediate page, exact records PASS")
        r = run('relic::functions checkpoint="fixture-checkpoint" | write_ndjson')
        assert len(r.stdout.splitlines()) == 3
        filtered = run(
            'relic::functions checkpoint="fixture-checkpoint", is_ecological=false | write_ndjson'
        )
        assert [json.loads(row)["id"] for row in filtered.stdout.splitlines()] == [
            "function-1"
        ]
        print("Revocation default and false/null source filtering: PASS")
        for selected in ["empty", "transient"]:
            mode = selected
            attempts = 0
            requests.clear()
            r = run('relic::functions checkpoint="fixture-checkpoint" | write_ndjson')
            assert (not r.stdout.strip()) if selected == "empty" else attempts == 4
            print(selected + ": PASS")
        for selected in [
            "auth",
            "permanent",
            "checkpoint",
            "schema",
            "malformed",
            "items",
            "loop",
            "duplicate",
            "origin",
            "link_checkpoint",
            "late_checkpoint",
            "late_schema",
        ]:
            mode = selected
            attempts = 0
            requests.clear()
            run('relic::functions checkpoint="fixture-checkpoint"', ok=False)
            if selected in [
                "auth",
                "permanent",
                "origin",
                "link_checkpoint",
                "late_checkpoint",
                "late_schema",
            ]:
                assert attempts == (3 if selected.startswith("late_") else 1), (
                    selected,
                    attempts,
                )
            print(selected + ": rejected PASS")
        mode = "seal_malformed"
        result = run('relic::seals checkpoint="fixture-checkpoint" | write_ndjson')
        assert json.loads(result.stdout)["seal_diagnostics"] == [
            "file.hashes must be an array"
        ]
        print("Malformed standard seal field diagnosed: PASS")
        mode = "normal"
        for path in sorted((package / "examples").glob("*.tql")):
            code = path.read_text()
            if path.stem == "export_ml_dataset":
                run(code)
            else:
                result = run(code + "\nwrite_ndjson")
                records = [
                    json.loads(row) for row in result.stdout.splitlines() if row.strip()
                ]
                if path.stem == "compiler_architecture_distribution":
                    assert sum(row["functions"] for row in records) == 3
                if path.stem == "ecological_artificial_split":
                    assert {row["is_ecological"] for row in records} == {
                        True,
                        False,
                        None,
                    }
                if path.stem == "bsim_fanout":
                    assert records == [{"bsim_id": "bsim-a", "occurrences": 2}]
                if path.stem == "hash_reuse":
                    assert len(records) == 2 and all(
                        row["binaries"] == 2 for row in records
                    )
                if path.stem == "classification_confidence":
                    assert {row["confidence"] for row in records} == {0.95, None}
                if path.stem == "provenance_completeness":
                    assert [row["id"] for row in records] == ["function-3"]
            print("example " + path.stem + ": PASS")
        run(
            f'from_file "{tmp}/analysis.parquet" {{ read_parquet }} | summarize n=count() | assert n == 3'
        )
        print("Parquet roundtrip: PASS")
        spec2 = importlib.util.spec_from_file_location(
            "export_analysis", ROOT / "tools/export_analysis.py"
        )
        exporter = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(exporter)
        args = [
            f"--config={config}",
            f"--endpoint={ep}",
            f"--package-dirs={tmp}/packages",
            "--console-verbosity=quiet",
        ]
        manifest = exporter.export(
            package / "examples/export_ml_dataset.tql",
            tmp / "published",
            "fixture-checkpoint",
            "relic.function-fact/1.0",
            args,
        )
        assert manifest["pipeline_sha256"] == exporter.digest(
            tmp / "published/pipeline.tql"
        )
        assert manifest["output_sha256"] == exporter.digest(
            tmp / "published/data.parquet"
        )
        assert manifest["tenzir_version"] == "6.21.0"
        assert manifest["relic_checkpoint"] == "fixture-checkpoint"
        assert json.loads((tmp / "published/manifest.yaml").read_text()) == manifest
        print("Atomic analysis manifest and digests: PASS")
        mode = "late_checkpoint"
        try:
            exporter.export(
                package / "examples/export_ml_dataset.tql",
                tmp / "failed",
                "fixture-checkpoint",
                "relic.function-fact/1.0",
                args,
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("failed export was published")
        assert not (tmp / "failed").exists()
        print("Late failure publishes no output or manifest: PASS")
    finally:
        node.terminate()
        try:
            node.wait(timeout=10)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait()
server.shutdown()
