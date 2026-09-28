"""
Fetch OTA packages from S3 using the AWS IoT Core credential provider.

WHY THIS EXISTS
    The job document historically carried a *presigned* S3 URL. SigV4 presigned
    URLs cap at 7 days, so a device that is offline longer than that receives a
    job it can never download - and the failure presents as a generic network
    error rather than "your URL expired".

WHAT IT DOES INSTEAD
    1. The device authenticates to the credential provider over HTTPS using its
       OWN X.509 certificate (mutual TLS) and receives short-lived IAM
       credentials.
    2. It reads the release object from S3 with those credentials, which boto3
       signs with SigV4.

    Nothing is presigned, so nothing expires. A device can be offline for a
    month and still update.

DEPENDENCIES
    Standard library only at import time. boto3 is imported lazily inside
    download_object(), so this module can be imported and unit-tested on a host
    without boto3 installed.
"""

import json
import os
import re
from pathlib import Path

CREDENTIAL_TIMEOUT_S = 30

# Default cap on a single S3 object, enforced DURING the transfer (see
# _CappedWriter). Callers that care about a specific limit - e.g. OTAHandler,
# which already caps HTTPS downloads at MAX_DOWNLOAD_BYTES - should pass their
# own value into make_fetcher(max_bytes=...) so there is one source of truth
# instead of two constants that can drift apart.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024

# Role aliases allow only alphanumerics and the = @ - symbols (AWS docs).
# Validated rather than interpolated-and-escaped: a role alias can never carry
# a path segment or query string, so there is no URL-injection surface.
_ALIAS_RE = re.compile(r"^[A-Za-z0-9=@._-]{1,128}$")

# Test seam: set to a callable(request, timeout, context) to intercept HTTP.
# Left as None in production, where urllib is used.
_urlopen = None


class CredentialError(RuntimeError):
    """Raised when the credential provider cannot be reached or refuses us.

    A refusal here almost always means the device certificate's IoT policy is
    missing iot:AssumeRoleWithCertificate on the role alias ARN.
    """


def credential_url(endpoint, role_alias):
    """Build the credential provider URL. Validates the alias first."""
    if not _ALIAS_RE.match(role_alias or ""):
        raise CredentialError("Rejected unsafe role alias: %r" % (role_alias,))
    endpoint = (endpoint or "").strip()
    if not endpoint:
        raise CredentialError("No IoT endpoint configured")
    return "https://%s/role-aliases/%s/credentials" % (endpoint, role_alias)


def _ssl_context(cert_path, key_path, ca_path):
    """mTLS context presenting the device certificate, verifying the server
    against our pinned root CA."""
    import ssl

    for label, p in (("certificate", cert_path), ("private key", key_path), ("root CA", ca_path)):
        if not Path(p).exists():
            raise CredentialError("Missing %s for mTLS: %s" % (label, p))

    ctx = ssl.create_default_context(cafile=str(ca_path))
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def _build_request(url, headers):
    """Build a real urllib.request.Request.

    FIX: this used to be a hand-rolled stand-in class that only carried
    full_url/url/headers/add_header(). That is not enough for
    urllib.request.urlopen(): OpenerDirector.open() reads req.type on its very
    first line, which urllib.request.Request only sets via the full_url
    property setter's internal _parse() call. The stand-in set self.full_url
    as a plain attribute, so req.type never existed and every real (non-test)
    credential fetch raised AttributeError - caught by the broad
    "except Exception" in fetch_credentials() and re-raised as a generic
    CredentialError, so the failure looked like a network/auth problem instead
    of a bug in this file. Every device using the S3 fetch path (OTA_ROLE_ALIAS
    set) has been unable to complete a credential exchange in production.

    Imported lazily so the module keeps no urllib dependency at import time,
    matching the module docstring's testability note.
    """
    import urllib.request

    return urllib.request.Request(url, headers=headers)


def fetch_credentials(endpoint, role_alias, thing_name, cert_path, key_path,
                      ca_path, timeout=CREDENTIAL_TIMEOUT_S, context=None):
    """Exchange the device certificate for short-lived AWS credentials.

    Returns the decoded response: accessKeyId, secretAccessKey, sessionToken
    and expiration. Raises CredentialError with an actionable message on any
    failure - never a bare exception, because the only thing worse than a
    failed OTA is one where the log says nothing useful.
    """
    url = credential_url(endpoint, role_alias)

    if not thing_name:
        raise CredentialError("No thing name configured")

    headers = {"x-amzn-iot-thingname": thing_name}

    # Imported lazily so the module imports cleanly where urllib is stubbed.
    if _urlopen is not None:
        opener = _urlopen
        request = _build_request(url, headers)
    else:
        import urllib.request
        opener = urllib.request.urlopen
        request = urllib.request.Request(url, headers=headers)

    ctx = context if context is not None else _ssl_context(cert_path, key_path, ca_path)

    try:
        resp = opener(request, timeout=timeout, context=ctx)
        with resp:
            body = resp.read()
    except Exception as e:
        code = getattr(e, "code", None)
        if code in (401, 403):
            raise CredentialError(
                "Credential provider refused the device (HTTP %s). Check that the "
                "device certificate's IoT policy grants "
                "iot:AssumeRoleWithCertificate on the role alias ARN." % code
            )
        raise CredentialError("Credential provider request failed: %s" % (e,))

    try:
        data = json.loads(body)
    except Exception as e:
        raise CredentialError("Credential provider returned non-JSON: %s" % (e,))

    for field in ("accessKeyId", "secretAccessKey", "sessionToken"):
        if not data.get(field):
            raise CredentialError("Credential response missing %s" % field)
    return data


def parse_s3_uri(uri):
    """s3://bucket/key -> (bucket, key). Rejects anything else loudly."""
    if not uri or not uri.startswith("s3://"):
        raise CredentialError("Not an s3:// URI: %r" % (uri,))
    rest = uri[len("s3://"):]
    bucket, sep, key = rest.partition("/")
    if not sep or not bucket or not key:
        raise CredentialError("Malformed s3:// URI (want s3://bucket/key): %r" % (uri,))
    return bucket, key


class _CappedWriter:
    """File-like wrapper that aborts a boto3 transfer once bytes written pass
    a fixed budget.

    FIX: download_object() previously called s3.download_file(), which streams
    the whole object to disk via boto3's transfer manager with no size limit
    of its own. The MAX_DOWNLOAD_BYTES-style cap was only checked AFTER the
    call returned, by which point a large or malicious object had already been
    written to disk in full - the exact "fill the disk mid-download" failure
    mode that OTAHandler._download() already guards against for the HTTPS
    path. Wrapping the destination file object lets boto3's own multipart
    download machinery hit the cap mid-transfer instead of after it.
    """

    def __init__(self, fileobj, max_bytes):
        self._f = fileobj
        self._max_bytes = max_bytes
        self._written = 0

    def write(self, data):
        self._written += len(data)
        if self._written > self._max_bytes:
            raise CredentialError(
                "S3 object exceeded the %d byte download cap mid-transfer"
                % self._max_bytes
            )
        return self._f.write(data)

    def __getattr__(self, name):
        # Delegate everything else (flush, close, tell, seekable, ...) so
        # boto3's transfer manager sees a normal file object.
        return getattr(self._f, name)


def download_object(credentials, bucket, key, dest_part, region,
                    timeout=60, max_bytes=DEFAULT_MAX_BYTES):
    """Read one object to dest_part using the supplied temporary credentials.

    Uses boto3 so SigV4 signing is not hand-rolled. Writes to dest_part, never
    to the final path - the caller renames atomically once the size is
    checked. Enforces max_bytes DURING the transfer via download_fileobj +
    _CappedWriter, not just by inspecting the file afterward.
    """
    import boto3  # lazy: not needed to import this module

    session = boto3.session.Session(
        aws_access_key_id=credentials["accessKeyId"],
        aws_secret_access_key=credentials["secretAccessKey"],
        aws_session_token=credentials["sessionToken"],
        region_name=region,
    )
    s3 = session.client("s3", region_name=region, config=_boto_config(timeout))

    try:
        with open(dest_part, "wb") as raw:
            capped = _CappedWriter(raw, max_bytes)
            s3.download_fileobj(bucket, key, capped)
    except CredentialError:
        # Already actionable (the cap message above) - pass through as-is.
        raise
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
        if code == "AccessDenied":
            raise CredentialError(
                "S3 AccessDenied for s3://%s/%s. The device role needs "
                "s3:GetObject on the object AND kms:Decrypt on the bucket key "
                "(the bucket is SSE-KMS encrypted)." % (bucket, key)
            )
        raise CredentialError("Download failed: %s" % (e,))

    return Path(dest_part).stat().st_size


def _boto_config(timeout):
    from botocore.config import Config
    return Config(
        connect_timeout=timeout,
        read_timeout=timeout,
        retries={"max_attempts": 2},
    )


def make_fetcher(endpoint, role_alias, thing_name, cert_path, key_path, ca_path,
                 region, timeout=CREDENTIAL_TIMEOUT_S, max_bytes=DEFAULT_MAX_BYTES):
    """Return a callable(uri, dest) suitable for OTAHandler(fetcher=...).

    The callable accepts an s3:// URI, fetches fresh credentials, downloads the
    object under a hard byte cap, and returns the bytes written.

    Credentials are fetched per download rather than cached. That is
    deliberate: a cached credential that expires mid-flight produces exactly
    the failure class this module exists to remove.

    Pass max_bytes explicitly from the caller's own size-cap constant (e.g.
    OTAHandler.MAX_DOWNLOAD_BYTES) so there is a single source of truth for
    the download limit shared by both the HTTPS and S3 paths.
    """

    def fetch(uri, dest):
        bucket, key = parse_s3_uri(uri)
        creds = fetch_credentials(endpoint, role_alias, thing_name,
                                  cert_path, key_path, ca_path, timeout=timeout)
        print("[OTA] Credentials acquired (expire %s)" % creds.get("expiration", "unknown"))
        return download_object(creds, bucket, key, dest, region,
                               timeout=timeout, max_bytes=max_bytes)

    return fetch