"""Tests for api_security exception classes."""

from core.api_security.exceptions import SpecParseError, UnresolvedRefError


def test_spec_parse_error_str_minimal():
    err = SpecParseError("msg")
    assert str(err) == "msg"


def test_spec_parse_error_str_full():
    err = SpecParseError(
        "msg", line_number=5, source="file.json", errors=["e1", "e2"]
    )
    s = str(err)
    assert "msg" in s
    assert "line 5" in s
    assert "[file.json]" in s
    assert "e1" in s


def test_unresolved_ref_error():
    err = UnresolvedRefError("bad ref", ref="#/components/X")
    assert err.ref == "#/components/X"
