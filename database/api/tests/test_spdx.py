"""SPDX license expression syntax."""

from __future__ import annotations

import pytest

from api.spdx import SpdxError, validate

VALID = [
    "MIT",
    "NONE",
    "NOASSERTION",
    "GPL-2.0+",
    "GPL-2.0-only WITH Classpath-exception-2.0",
    "MIT OR Apache-2.0",
    "(MIT OR Apache-2.0) AND BSD-3-Clause",
    "LicenseRef-acme-internal",
    "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
    "Apache-2.0 WITH AdditionRef-acme-exception",
    "((MIT))",
    "MIT AND (LGPL-2.1-or-later OR BSD-3-Clause WITH LLVM-exception)",
]

INVALID = [
    "",
    "   ",
    "MIT and Apache-2.0",          # operators are case-sensitive
    "MIT Apache-2.0",              # missing operator
    "MIT OR",
    "AND MIT",
    "(MIT",
    "MIT)",
    "MIT WITH",
    "MIT WITH (Classpath-exception-2.0)",
    "MIT WITH GPL-2.0 WITH X",
    "NONE OR MIT",                 # special values only on their own
    "MIT/Apache-2.0",
    "LicenseRef-",
    "DocumentRef-x:MIT",
    "MIT WITH AdditionRef-",
    "MIT;rm",
    "(" * 40 + "MIT" + ")" * 40,
    "MIT OR " * 200 + "MIT",       # too long
]


@pytest.mark.parametrize("expression", VALID)
def test_valid_expressions(expression):
    assert validate(expression) == expression


@pytest.mark.parametrize("expression", INVALID)
def test_invalid_expressions(expression):
    with pytest.raises(SpdxError):
        validate(expression)
