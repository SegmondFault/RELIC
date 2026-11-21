"""Transport-level protections: body limits, response headers, rate limits."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from typing import Awaitable, Callable

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_JSON_413 = b'{"detail":"Request body too large"}'

_SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
]
_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


class _BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject request bodies above ``max_bytes``, declared or streamed."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._reject(send, 400, b'{"detail":"Invalid Content-Length"}')
                    return
                if declared > self.max_bytes:
                    await self._reject(send, 413, _JSON_413)
                    return

        received = 0
        exceeded = False
        replaced = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            # Frameworks may swallow the exception raised while reading the
            # body and answer with their own error; replace that with 413.
            nonlocal replaced
            if replaced:
                return
            if exceeded and message["type"] == "http.response.start":
                replaced = True
                await self._reject(send, 413, _JSON_413)
                return
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            pass
        if exceeded and not replaced:
            replaced = True
            await self._reject(send, 413, _JSON_413)

    @staticmethod
    async def _reject(send: Send, status: int, body: bytes) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                    *_SECURITY_HEADERS,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """Defence in depth: Caddy sets these too, but the API must not rely on it."""

    def __init__(self, app: ASGIApp, *, allow_docs: bool) -> None:
        self.app = app
        self.allow_docs = allow_docs

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        relaxed = self.allow_docs and scope["path"].startswith(_DOC_PATHS)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"server"
                ]
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS:
                    if relaxed and name == b"content-security-policy":
                        continue
                    if name not in present:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RateLimiter:
    """In-memory sliding-window limiter keyed by (bucket, client address).

    State is per process: run the API as a single worker behind Caddy, or move
    this to a shared store before scaling out. The number of tracked keys is
    bounded so a flood of distinct addresses cannot exhaust memory.
    """

    def __init__(self, max_keys: int = 100_000) -> None:
        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._max_keys = max_keys

    def hit(self, bucket: str, client: str, limit: int, window_seconds: float) -> float | None:
        """Record a hit; return seconds to wait if the limit is exceeded."""
        now = time.monotonic()
        key = (bucket, client)
        hits = self._hits.get(key)
        if hits is None:
            hits = deque()
            self._hits[key] = hits
            while len(self._hits) > self._max_keys:
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(key)
        while hits and hits[0] <= now - window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            return max(hits[0] + window_seconds - now, 0.0)
        hits.append(now)
        return None

    def reset(self) -> None:
        self._hits.clear()


def client_address(request: Request) -> str:
    # Uvicorn's --proxy-headers rewrites request.client from Caddy's
    # X-Forwarded-For; the API port itself is never published.
    return request.client.host if request.client else "unknown"


def rate_limit(
    bucket: str,
    limit: Callable[[Request], int],
    window_seconds: float,
) -> Callable[[Request], Awaitable[None]]:
    async def dependency(request: Request) -> None:
        limiter: RateLimiter = request.app.state.rate_limiter
        retry_after = limiter.hit(bucket, client_address(request), limit(request), window_seconds)
        if retry_after is not None:
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

    return dependency
