"""Offline unit tests for LucidScanner — no network calls.

These exercise the pure logic: the Finding model, severity ordering,
IP/CDN classification, subdomain parsing, and Markdown rendering.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import json as _json

from lucid_scanner import (  # noqa: E402
    Finding,
    Scanner,
    SEV_ORDER,
    extract_supabase_creds,
    render_markdown,
)


def _fake_jwt(role):
    """Build an unsigned JWT-shaped token whose payload carries a role."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        _json.dumps({"iss": "supabase", "role": role}).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}.{'s' * 20}"


def test_finding_rejects_unknown_severity():
    with pytest.raises(AssertionError):
        Finding("catastrophic", "nope")


def test_finding_to_dict_roundtrips_fields():
    f = Finding("high", "Open admin", evidence="200 OK", impact="x", fix="y")
    d = f.to_dict()
    assert d == {
        "severity": "high",
        "title": "Open admin",
        "evidence": "200 OK",
        "impact": "x",
        "fix": "y",
    }


def test_severity_order_is_descending():
    assert SEV_ORDER == ["critical", "high", "medium", "low", "info"]


@pytest.mark.parametrize(
    "url,expected_host,expected_scheme",
    [
        ("example.com", "example.com", "https"),
        ("https://example.com/", "example.com", "https"),
        ("http://sub.example.com/path", "sub.example.com", "http"),
    ],
)
def test_scanner_normalizes_url(url, expected_host, expected_scheme):
    s = Scanner(url)
    assert s.host == expected_host
    assert s.scheme == expected_scheme
    assert s.base == f"{expected_scheme}://{expected_host}"


@pytest.mark.parametrize(
    "ip,provider",
    [
        ("3.21.0.1", "AWS"),
        ("52.1.2.3", "AWS"),
        ("216.150.1.1", "Vercel"),
        ("5.75.10.10", "Hetzner"),
        ("216.239.1.1", "Google"),
        ("198.51.100.7", "unknown"),
    ],
)
def test_ip_classification(ip, provider):
    s = Scanner("example.com")
    assert s._classify_ip(ip) == provider


def test_crt_parser_filters_wildcards_and_foreign_hosts():
    s = Scanner("example.com")
    payload = (
        '[{"name_value": "a.example.com\\n*.example.com"},'
        ' {"name_value": "b.example.com"},'
        ' {"name_value": "evil.attacker.net"}]'
    )
    names = s._parse_crt(payload)
    assert names == {"a.example.com", "b.example.com"}


def test_hackertarget_parser_keeps_only_matching_suffix():
    s = Scanner("example.com")
    text = "a.example.com,1.2.3.4\nb.other.com,5.6.7.8\nc.example.com,9.9.9.9"
    names = s._parse_hackertarget(text)
    assert names == {"a.example.com", "c.example.com"}


def test_render_markdown_includes_summary_and_findings():
    findings = [
        Finding("critical", "MySQL exposed", evidence="port 3306 open"),
        Finding("low", "Missing nosniff header"),
    ]
    md = render_markdown("https://example.com", findings)
    assert "# LucidScanner report — https://example.com" in md
    assert "MySQL exposed" in md
    assert "port 3306 open" in md
    assert "| 🔴 Critical | 1 |" in md
    assert "| 🟢 Low | 1 |" in md


def test_render_markdown_handles_no_findings():
    md = render_markdown("https://example.com", [])
    assert "## Summary" in md
    # every severity row present with a zero count
    for label in ("Critical", "High", "Medium", "Low", "Info"):
        assert f"{label} | 0 |" in md


def test_extract_supabase_creds_finds_url_and_anon_key():
    anon = _fake_jwt("anon")
    text = (
        'const c=createClient("https://zqalbxcyacmeeevarxwy.supabase.co",'
        f'"{anon}");'
    )
    url, key = extract_supabase_creds(text)
    assert url == "https://zqalbxcyacmeeevarxwy.supabase.co"
    assert key == anon


def test_extract_supabase_creds_ignores_service_role_key():
    # A service_role key must never be returned for probing.
    service = _fake_jwt("service_role")
    text = f'url="https://abcdefghijklmnop.supabase.co" key="{service}"'
    url, key = extract_supabase_creds(text)
    assert url == "https://abcdefghijklmnop.supabase.co"
    assert key is None


def test_extract_supabase_creds_returns_none_without_supabase():
    url, key = extract_supabase_creds("just some unrelated bundle code")
    assert url is None and key is None
