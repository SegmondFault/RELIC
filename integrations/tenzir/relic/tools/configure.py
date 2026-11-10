"""Render nonsecret deployment inputs into a staging copy, never the source tree."""

import argparse
import shutil
from pathlib import Path


def configure(
    source,
    destination,
    api_endpoint="https://relic.invalid",
    default_page_size=500,
    request_timeout="30s",
    maximum_retries=3,
    fixture=False,
):
    from urllib.parse import urlsplit
    import re

    u = urlsplit(api_endpoint)
    if (
        (
            u.scheme != "https"
            and not (fixture and u.scheme == "http" and u.hostname == "127.0.0.1")
        )
        or not u.netloc
        or u.username
        or u.password
        or u.query
        or u.fragment
        or u.path
    ):
        raise ValueError("api_endpoint must be a credential-free HTTPS origin")
    if not u.hostname or not re.fullmatch(r"[A-Za-z0-9.:-]+", u.hostname):
        raise ValueError("api_endpoint hostname is invalid")
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError("api_endpoint port is invalid")
    if not 1 <= default_page_size <= 10000 or not 0 <= maximum_retries <= 10:
        raise ValueError("page size or retry bound invalid")
    if not re.fullmatch(r"[1-9][0-9]*(ms|s|m)", request_timeout):
        raise ValueError("request_timeout must be a positive ms/s/m duration")
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination == source or source in destination.parents or destination.exists():
        raise ValueError("destination must be a new directory outside the package")
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "config.yaml", "._*"),
    )
    values = dict(
        api_endpoint=api_endpoint,
        default_page_size=str(default_page_size),
        request_timeout=request_timeout,
        maximum_retries=str(maximum_retries),
    )
    for file in destination.rglob("*.tql"):
        text = file.read_text()
        for key, value in values.items():
            text = text.replace("{{ inputs." + key + " }}", value)
        file.write_text(text)
    return destination


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("destination", type=Path)
    p.add_argument("--api-endpoint", required=True)
    p.add_argument("--default-page-size", type=int, default=500)
    p.add_argument("--request-timeout", default="30s")
    p.add_argument("--maximum-retries", type=int, default=3)
    a = p.parse_args()
    configure(
        Path(__file__).resolve().parents[1],
        a.destination,
        a.api_endpoint,
        a.default_page_size,
        a.request_timeout,
        a.maximum_retries,
    )
