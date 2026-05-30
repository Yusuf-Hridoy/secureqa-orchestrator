"""Tests for the API7 SSRF generator."""


from core.api_security.generators.api7_ssrf import SSRF_PAYLOADS, SSRFGenerator
from core.api_security.test_models import OWASPAPICategory


def test_no_url_params_no_tests(simple_api_spec):
    """simple_api_spec has no URL-like params → no SSRF tests."""
    gen = SSRFGenerator()
    assert gen.generate(simple_api_spec) == []


def test_ssrf_candidate_endpoint(ssrf_candidate_spec):
    """ssrf_candidate_spec has /fetch with url + callback_url body props."""
    gen = SSRFGenerator()
    tests = gen.generate(ssrf_candidate_spec)
    # 2 url-like params × N payloads
    assert len(tests) == 2 * len(SSRF_PAYLOADS)


def test_aws_metadata_payload_present(ssrf_candidate_spec):
    gen = SSRFGenerator()
    tests = gen.generate(ssrf_candidate_spec)
    assert any("169.254.169.254" in (t.payload.body or {}).get("url", "") or
               "169.254.169.254" in (t.payload.body or {}).get("callback_url", "")
               for t in tests)


def test_category_is_api7(ssrf_candidate_spec):
    gen = SSRFGenerator()
    for t in gen.generate(ssrf_candidate_spec):
        assert t.owasp_category == OWASPAPICategory.API7_SSRF
