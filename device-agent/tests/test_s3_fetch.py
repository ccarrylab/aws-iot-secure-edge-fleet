"""
Unit tests for device-agent/s3_fetch.py.

No network, no boto3, no real certificates. Everything that talks to the
outside world is either pure (parse_s3_uri, credential_url) or goes through
the _urlopen / context seams so it can be stubbed.
"""

import io
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import s3_fetch
from s3_fetch import (
    CredentialError,
    _CappedWriter,
    credential_url,
    fetch_credentials,
    make_fetcher,
    parse_s3_uri,
)


# ---------------------------------------------------------------------------
# credential_url / alias validation
# ---------------------------------------------------------------------------

class TestCredentialUrl:
    def test_builds_expected_url(self):
        url = credential_url("abc-ats.iot.us-east-1.amazonaws.com", "my-alias")
        assert url == "https://abc-ats.iot.us-east-1.amazonaws.com/role-aliases/my-alias/credentials"

    def test_rejects_empty_alias(self):
        with pytest.raises(CredentialError, match="unsafe role alias"):
            credential_url("endpoint", "")

    def test_rejects_path_injection(self):
        with pytest.raises(CredentialError, match="unsafe role alias"):
            credential_url("endpoint", "../evil")

    def test_rejects_empty_endpoint(self):
        with pytest.raises(CredentialError, match="No IoT endpoint"):
            credential_url("", "alias")


# ---------------------------------------------------------------------------
# parse_s3_uri
# ---------------------------------------------------------------------------

class TestParseS3Uri:
    def test_happy_path(self):
        assert parse_s3_uri("s3://my-bucket/packages/1.0.0.tar.gz") == (
            "my-bucket",
            "packages/1.0.0.tar.gz",
        )

    def test_rejects_https(self):
        with pytest.raises(CredentialError, match="Not an s3://"):
            parse_s3_uri("https://example.com/pkg.tar.gz")

    def test_rejects_missing_key(self):
        with pytest.raises(CredentialError, match="Malformed"):
            parse_s3_uri("s3://bucket-only")

    def test_rejects_empty(self):
        with pytest.raises(CredentialError, match="Not an s3://"):
            parse_s3_uri("")


# ---------------------------------------------------------------------------
# _CappedWriter
# ---------------------------------------------------------------------------

class TestCappedWriter:
    def test_writes_under_cap(self):
        buf = io.BytesIO()
        writer = _CappedWriter(buf, max_bytes=100)
        writer.write(b"hello")
        assert buf.getvalue() == b"hello"
        assert writer._written == 5

    def test_raises_when_cap_exceeded(self):
        buf = io.BytesIO()
        writer = _CappedWriter(buf, max_bytes=10)
        writer.write(b"1234567890")  # exactly at limit is ok
        with pytest.raises(CredentialError, match="exceeded the 10 byte"):
            writer.write(b"x")


# ---------------------------------------------------------------------------
# fetch_credentials (stubbed HTTP)
# ---------------------------------------------------------------------------

class TestFetchCredentials:
    def test_happy_path(self, monkeypatch, tmp_path):
        body = json.dumps({
            "accessKeyId": "AKIA",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": "2099-01-01T00:00:00Z",
        }).encode()

        class FakeResp:
            def read(self):
                return body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        def fake_urlopen(req, timeout=None, context=None):
            return FakeResp()

        monkeypatch.setattr(s3_fetch, "_urlopen", fake_urlopen)

        # Provide dummy cert paths so _ssl_context is not called when context= is given
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_text("dummy")

        data = fetch_credentials(
            "endpoint", "alias", "thing-1",
            str(cert), str(key), str(ca),
            context=object(),  # skip real SSL
        )
        assert data["accessKeyId"] == "AKIA"
        assert data["sessionToken"] == "token"

    def test_403_gives_actionable_message(self, monkeypatch, tmp_path):
        class Forbidden(Exception):
            code = 403

        def fake_urlopen(req, timeout=None, context=None):
            raise Forbidden()

        monkeypatch.setattr(s3_fetch, "_urlopen", fake_urlopen)

        cert = tmp_path / "c.pem"
        key = tmp_path / "k.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_text("x")

        with pytest.raises(CredentialError, match="iot:AssumeRoleWithCertificate"):
            fetch_credentials(
                "endpoint", "alias", "thing-1",
                str(cert), str(key), str(ca),
                context=object(),
            )

    def test_missing_thing_name(self, tmp_path):
        cert = tmp_path / "c.pem"
        key = tmp_path / "k.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_text("x")
        with pytest.raises(CredentialError, match="No thing name"):
            fetch_credentials(
                "endpoint", "alias", "",
                str(cert), str(key), str(ca),
                context=object(),
            )


# ---------------------------------------------------------------------------
# make_fetcher wiring (no real download)
# ---------------------------------------------------------------------------

class TestMakeFetcher:
    def test_returns_callable(self, tmp_path):
        cert = tmp_path / "c.pem"
        key = tmp_path / "k.pem"
        ca = tmp_path / "ca.pem"
        for p in (cert, key, ca):
            p.write_text("x")
        fetcher = make_fetcher(
            "endpoint", "alias", "thing",
            str(cert), str(key), str(ca),
            region="us-east-1",
            max_bytes=1024,
        )
        assert callable(fetcher)
