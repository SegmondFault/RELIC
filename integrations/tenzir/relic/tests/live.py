# timeout: 60
"""Disabled by default. Uses an installed package and named Tenzir secret."""

import os
import subprocess

if os.environ.get("RELIC_LIVE_TEST") != "1":
    print("SKIP: live API test disabled")
else:
    if not os.environ.get("RELIC_CHECKPOINT"):
        raise RuntimeError("RELIC_CHECKPOINT required")
    # Do not use head: the smoke test must detect late pagination failures too.
    subprocess.run(
        ["tenzir", 'relic::functions checkpoint=env("RELIC_CHECKPOINT") | discard'],
        check=True,
        timeout=50,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("PASS: read-only live function export completed")
