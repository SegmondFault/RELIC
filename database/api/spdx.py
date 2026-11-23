"""SPDX license expression syntax (SPDX 2.3, Annex D).

Checks syntax only: identifiers are not looked up in the SPDX License List,
so new or unusual IDs are accepted and local licences use ``LicenseRef-``.
``NONE`` and ``NOASSERTION`` are allowed only as the whole expression.
Operators are case-sensitive (``AND``, ``OR``, ``WITH``); ``WITH`` binds
tighter than ``AND``, which binds tighter than ``OR``. The expression is
stored and signed exactly as given, never normalised.
"""

from __future__ import annotations

import re

MAX_LENGTH = 1000
MAX_DEPTH = 32

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")
_IDSTRING = r"[A-Za-z0-9.\-]+"
_REFERENCE = ("LicenseRef-", "DocumentRef-", "AdditionRef-")
_LICENSE = re.compile(
    rf"(?:{_IDSTRING}\+?|LicenseRef-{_IDSTRING}|DocumentRef-{_IDSTRING}:LicenseRef-{_IDSTRING})"
)
_LICENSE_REF = re.compile(rf"(?:DocumentRef-{_IDSTRING}:)?LicenseRef-{_IDSTRING}")
_EXCEPTION = re.compile(
    rf"(?:{_IDSTRING}|AdditionRef-{_IDSTRING}|DocumentRef-{_IDSTRING}:AdditionRef-{_IDSTRING})"
)
_EXCEPTION_REF = re.compile(rf"(?:DocumentRef-{_IDSTRING}:)?AdditionRef-{_IDSTRING}")


def _is_license(token: str) -> bool:
    if token.startswith(_REFERENCE):  # a reference must be complete, not a bare prefix
        return _LICENSE_REF.fullmatch(token) is not None
    return _LICENSE.fullmatch(token) is not None


def _is_exception(token: str) -> bool:
    if token.startswith(_REFERENCE):
        return _EXCEPTION_REF.fullmatch(token) is not None
    return _EXCEPTION.fullmatch(token) is not None
_OPERATORS = {"AND", "OR", "WITH"}
_SPECIAL = {"NONE", "NOASSERTION"}


class SpdxError(ValueError):
    pass


def _tokens(expression: str) -> list[str]:
    tokens, position = [], 0
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if match is None:
            break
        tokens.append(match.group(1))
        position = match.end()
    if expression[position:].strip():
        raise SpdxError("unexpected trailing characters")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise SpdxError("expression ends early")
        self.index += 1
        return token

    def expression(self, depth: int) -> None:  # or-expression
        self.and_expression(depth)
        while self.peek() == "OR":
            self.take()
            self.and_expression(depth)

    def and_expression(self, depth: int) -> None:
        self.with_expression(depth)
        while self.peek() == "AND":
            self.take()
            self.with_expression(depth)

    def with_expression(self, depth: int) -> None:
        if self.peek() == "(":
            if depth >= MAX_DEPTH:
                raise SpdxError("parentheses nested too deeply")
            self.take()
            self.expression(depth + 1)
            if self.take() != ")":
                raise SpdxError("missing closing parenthesis")
            return
        token = self.take()
        if token in _OPERATORS or token in _SPECIAL or token == ")" or not _is_license(token):
            raise SpdxError(f"expected a license identifier, got {token!r}")
        if self.peek() == "WITH":
            self.take()
            exception = self.take()
            if exception in _OPERATORS or exception in _SPECIAL or not _is_exception(exception):
                raise SpdxError(f"expected an exception identifier, got {exception!r}")


def validate(expression: str) -> str:
    """Return ``expression`` unchanged if it is a valid SPDX expression."""
    if len(expression) > MAX_LENGTH:
        raise SpdxError(f"longer than {MAX_LENGTH} characters")
    if expression in _SPECIAL:
        return expression
    tokens = _tokens(expression)
    if not tokens:
        raise SpdxError("empty expression")
    parser = _Parser(tokens)
    parser.expression(0)
    if parser.peek() is not None:
        raise SpdxError(f"unexpected {parser.peek()!r}")
    return expression
