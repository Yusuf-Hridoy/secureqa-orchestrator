"""Tests for the abstract parser base class."""

import pytest

from core.api_security.exceptions import SpecParseError
from core.api_security.models import APISpec, SpecFormat
from core.api_security.parsers.base import SpecParser


class DummyParser(SpecParser):
    """Minimal concrete impl for testing."""

    name = "dummy"

    def can_parse(self, content):
        return True

    def parse(self, content):
        data = self._ensure_dict(content)
        return APISpec(
            name=data.get("name", "test"), source_format=SpecFormat.OPENAPI_3_0
        )


def test_ensure_dict_passes_through_dict():
    parser = DummyParser()
    assert parser._ensure_dict({"name": "test"}) == {"name": "test"}


def test_ensure_dict_parses_json_string():
    parser = DummyParser()
    result = parser._ensure_dict('{"name": "test"}')
    assert result == {"name": "test"}


def test_ensure_dict_parses_yaml_string():
    parser = DummyParser()
    result = parser._ensure_dict("name: test\nversion: 1.0")
    assert result == {"name": "test", "version": 1.0}


def test_ensure_dict_handles_bytes():
    parser = DummyParser()
    result = parser._ensure_dict(b'{"name": "test"}')
    assert result == {"name": "test"}


def test_ensure_dict_rejects_invalid_content():
    parser = DummyParser()
    with pytest.raises(SpecParseError):
        parser._ensure_dict("this is :: not valid : json or : yaml ::::")


def test_warnings_list_starts_empty():
    parser = DummyParser()
    assert parser._warnings == []


def test_add_warning_appends_to_list():
    parser = DummyParser()
    parser._add_warning("TEST_CODE", "Test message", location="/paths/foo")
    assert len(parser._warnings) == 1
    assert parser._warnings[0].code == "TEST_CODE"
    assert parser._warnings[0].location == "/paths/foo"


def test_lenient_mode_default_false():
    assert DummyParser().lenient is False
    assert DummyParser(lenient=True).lenient is True
