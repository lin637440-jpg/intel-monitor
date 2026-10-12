import pytest
from app.monitor.service import (
    search_vulnerabilities,
    enrich_vulnerability,
)
from common.exceptions import NotFoundError


def test_search_returns_list():
    r = search_vulnerabilities("WordPress")
    assert isinstance(r, list)
    assert len(r) > 0


def test_search_empty_keyword():
    r = search_vulnerabilities("")
    assert r == []


def test_search_no_match():
    r = search_vulnerabilities("zzz_no_such_keyword_zzz")
    assert r == []


def test_enrich_existing():
    r = enrich_vulnerability("CVE-2026-13144")
    assert r.get("id") == "CVE-2026-13144"
    assert "risk_score" in r
    assert "risk_level" in r


def test_enrich_not_found():
    with pytest.raises(NotFoundError):
        enrich_vulnerability("CVE-9999-99999")


def test_enrich_empty():
    with pytest.raises(NotFoundError):
        enrich_vulnerability("")