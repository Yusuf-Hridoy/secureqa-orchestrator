"""Tests for format auto-detection and dispatch."""

import json
from pathlib import Path

import pytest

from core.api_security import parse_spec
from core.api_security.exceptions import UnsupportedSpecError
from core.api_security.models import SpecFormat
from core.api_security.parsers.auto_detect import detect_format
from core.api_security.parsers.openapi_parser import OpenAPIParser
from core.api_security.parsers.postman_parser import PostmanParser

FIXTURES = Path("tests/fixtures/specs")


def test_detects_openapi_3_0():
    data = json.loads((FIXTURES / "petstore_openapi_3_0.json").read_text())
    parser = detect_format(data)
    assert isinstance(parser, OpenAPIParser)


def test_detects_openapi_3_1_yaml():
    text = (FIXTURES / "petstore_openapi_3_1.yaml").read_text()
    parser = detect_format(text)
    assert isinstance(parser, OpenAPIParser)


def test_detects_postman_v2_1():
    data = json.loads((FIXTURES / "postman_collection_v2_1.json").read_text())
    parser = detect_format(data)
    assert isinstance(parser, PostmanParser)


def test_returns_none_for_unknown_format():
    parser = detect_format({"random": "data"})
    assert parser is None


def test_parse_spec_openapi():
    data = json.loads((FIXTURES / "petstore_openapi_3_0.json").read_text())
    spec = parse_spec(data)
    assert spec.source_format == SpecFormat.OPENAPI_3_0
    assert spec.endpoint_count() == 4


def test_parse_spec_postman():
    data = json.loads((FIXTURES / "postman_collection_v2_1.json").read_text())
    spec = parse_spec(data)
    assert spec.source_format == SpecFormat.POSTMAN_2_1


def test_parse_spec_raises_on_unknown():
    with pytest.raises(UnsupportedSpecError):
        parse_spec({"completely": "unknown"})


def test_parse_spec_accepts_bytes():
    raw = (FIXTURES / "petstore_openapi_3_0.json").read_bytes()
    spec = parse_spec(raw)
    assert spec.endpoint_count() == 4


def test_parse_spec_accepts_string():
    text = (FIXTURES / "petstore_openapi_3_0.json").read_text()
    spec = parse_spec(text)
    assert spec.endpoint_count() == 4
