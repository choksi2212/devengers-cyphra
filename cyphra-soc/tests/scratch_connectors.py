"""Scratch verification for ingest.connectors — transport, auth, windows, pagination.

    python tests/scratch_connectors.py

Ten connectors read ten APIs that cannot be reached from this host: each needs a
tenant, a licence and a credential. So the things that break in production are
precisely the things no live smoke test would ever catch, and this suite exists to
catch them against *captured vendor shapes* instead — Okta's comma-bearing cursor,
CloudTrail's JSON-string-inside-JSON, Graph's self-contained ``nextLink``, AWS's
non-IP ``sourceIPAddress``.

Two things here are pinned against outside authority rather than against themselves:

* **SigV4** is compared byte-for-byte with :mod:`botocore` — AWS's own production
  signer — across six request shapes, and the signing-key derivation is asserted
  against the constant AWS publishes in its signing documentation. A signer verified
  only against its own output proves nothing; the failure mode is a single
  ``SignatureDoesNotMatch`` that reads exactly like a wrong secret key.
* **Timestamp parsing** is asserted against the six spellings these APIs actually
  emit, including the seven-fractional-digit .NET form, because a timestamp silently
  parsed as local time shifts every event on this host by five and a half hours and
  breaks correlation without breaking anything visible.
"""

import asyncio
import base64
import calendar
import json
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, ".")

from core.config import Credential
from ingest.connectors.auth import (
    JWT_LIFETIME_SECONDS,
    REFRESH_MARGIN_SECONDS,
    Authorizer,
    CredentialsIncomplete,
    OAuth2ClientCredentials,
    ServiceAccount,
    ServiceAccountJwtAuth,
    SigV4Auth,
    StaticHeaderAuth,
    Token,
    _uri_encode,
    require,
    sigv4_signing_key,
)
from ingest.connectors.base import (
    Connector,
    ConnectorFleet,
    ConnectorSpec,
    DocStoreCheckpoints,
    MemoryCheckpoints,
    TimeWindow,
    WindowPlanner,
    dig,
    first,
    iso8601,
    normalise_records,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import (
    MAX_HONOURED_WAIT,
    RETRY_STATUSES,
    ApiClient,
    AuthError,
    BadPayload,
    HttpError,
    HttpResponse,
    RateLimiter,
    Request,
    RetryPolicy,
    TransientError,
    _vendor_error,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


class Clock:
    """A clock the test drives, so elapsed time is a decision not a wait."""

    def __init__(self, start=1_800_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        return self.now


class Sleeper:
    """Time advances only by sleeping, so waits are asserted rather than endured.

    Injecting a no-op sleep and leaving the clock real *looks* equivalent and is not:
    :meth:`RateLimiter.acquire` re-checks its floor in a loop, so a no-op sleep against
    a real ``time.monotonic`` spins roughly a million times per honoured second. The
    injected clock has to move when the injected sleep is taken.
    """

    def __init__(self, start: float = 10_000.0):
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(float(seconds))
        self.now += max(0.0, float(seconds))
        await asyncio.sleep(0)

    def reset(self) -> None:
        self.slept.clear()


SLEEP = Sleeper()


def limiter(rate: float = 1000.0, burst: int = 1000, **kw):
    """A limiter wide enough not to be the thing under test, on the fake clock."""
    return RateLimiter(rate, burst, clock=SLEEP, sleep=SLEEP.sleep, **kw)


def cred(name, value, env=None):
    return Credential(
        name=name, env_var=env or name.upper(), purpose=f"test {name}",
        secret=value, source="test",
    )


# ── a scriptable transport ──────────────────────────────────────────────────


class ScriptedTransport:
    """Replays captured vendor responses. The whole point of the Transport seam.

    Each script entry is ``(status, headers, body)``; a callable entry is handed the
    request so a test can assert on what was actually sent — which is how the
    "``nextLink`` must be followed verbatim" rule is checked, since the bug it
    prevents is a *duplicated* query parameter, visible only in the outgoing URL.
    """

    def __init__(self, script):
        self.script = list(script)
        self.seen = []
        self.closed = False

    async def send(self, request, timeout_s=60.0):
        self.seen.append(request)
        if not self.script:
            raise AssertionError(f"scripted transport exhausted at {request.url}")
        entry = self.script.pop(0)
        if callable(entry):
            entry = entry(request)
        status, headers, body = entry
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        return HttpResponse(status=status, headers=headers or {}, body=body,
                            url=request.url)

    async def aclose(self):
        self.closed = True


# ── 1. HTTP layer ───────────────────────────────────────────────────────────


async def test_http():
    print("\n[http] response parsing, rate limits, retries")

    r = HttpResponse(status=200, headers={"Content-Type": "application/json",
                                         "X-Rate-Limit-Remaining": "17"},
                     body=b'{"a":1}')
    check("header lookup is case-insensitive, because HTTP is and vendors are "
          "inconsistent about it",
          r.header("content-type") == "application/json"
          and r.header("X-RATE-LIMIT-REMAINING") == "17")
    check("a JSON body parses", r.json() == {"a": 1})

    html = HttpResponse(status=200, headers={}, body=b"<html>proxy error</html>")
    try:
        html.json()
        check("an HTML body raises BadPayload with a snippet", False)
    except BadPayload as exc:
        check("an HTML body raises BadPayload with a snippet",
              "html" in str(exc).lower(),
              "a 200 carrying HTML is a corporate proxy, not a vendor bug — the "
              "snippet is what tells an operator which")

    # Okta's Link header. The cursor value contains a comma, which is why this
    # cannot be split on "," — the single most likely way to break Okta pagination
    # while appearing to work on the first page.
    okta = HttpResponse(
        status=200,
        headers={"link": '<https://x.okta.com/api/v1/logs?since=2026-01-01>; rel="self", '
                         '<https://x.okta.com/api/v1/logs?after=1735689600000,abc,def>; rel="next"'},
        body=b"[]",
    )
    check("an RFC 5988 next link survives a comma inside the cursor value",
          okta.link("next") == "https://x.okta.com/api/v1/logs?after=1735689600000,abc,def",
          "Okta's after= cursor is an opaque string that contains commas; splitting "
          "the Link header on ',' truncates it and the next page 400s")
    check("...and rel=self is not mistaken for it",
          okta.link("self") == "https://x.okta.com/api/v1/logs?since=2026-01-01")
    check("a missing rel is empty, not an exception",
          okta.link("prev") == "")

    # retry_after, three encodings, all real
    clock = Clock()
    lim = RateLimiter(100.0, 100, name="t", clock=clock, sleep=SLEEP.sleep)
    delta = HttpResponse(status=429, headers={"retry-after": "42"}, body=b"")
    check("retry-after as delta seconds is read as seconds",
          abs((lim.retry_after(delta) or 0) - 42.0) < 0.01)

    future = time.gmtime(time.time() + 30)
    http_date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", future)
    dated = HttpResponse(status=429, headers={"retry-after": http_date}, body=b"")
    got = lim.retry_after(dated) or 0
    check("retry-after as an HTTP-date is differenced against now",
          25 <= got <= 35, f"{got:.1f}s from {http_date!r}")

    epoch_reset = HttpResponse(
        status=429,
        headers={"x-rate-limit-reset": str(int(time.time() + 60))},
        body=b"",
    )
    got = lim.retry_after(epoch_reset) or 0
    check("an absolute epoch reset is differenced against wall-clock, not monotonic",
          50 <= got <= 70,
          f"{got:.1f}s — Okta and CrowdStrike send an absolute epoch while the token "
          "bucket runs on time.monotonic; subtracting one from the other yields a "
          "wait of about fifty-six years")

    silly = HttpResponse(status=429, headers={"retry-after": "99999"}, body=b"")
    check("an absurd hint is reported faithfully by retry_after...",
          abs((lim.retry_after(silly) or 0) - 99999.0) < 0.01,
          "reading and honouring are separate: retry_after says what the vendor "
          "asked for, and the two places that act on it decide what to grant")
    check("...but capped where it is acted on",
          lim.hold_for(99999.0) == MAX_HONOURED_WAIT,
          f"capped at {MAX_HONOURED_WAIT:.0f}s — a CDN in front of one of these APIs "
          "asking for a 28-hour wait would otherwise stop collection for a day while "
          "the source still read as mid-cycle rather than failed")

    SLEEP.reset()
    t = ScriptedTransport([(429, {"retry-after": "99999"}, b"slow down"),
                           (200, {}, {"ok": True})])
    client = ApiClient(t, limiter=limiter(),
                       retry=RetryPolicy(attempts=3, jitter=False), sleep=SLEEP.sleep)
    resp = await client.send(Request("GET", "https://api.example.com/x"))
    check("...including inside the retry loop, which is a separate sleep from the "
          "limiter's floor and was the one that could still park a connector for a day",
          resp.status == 200 and max(SLEEP.slept) <= MAX_HONOURED_WAIT
          and client.stats().get("oversized_retry_hints") == 1,
          f"slept {[round(s, 2) for s in SLEEP.slept]}; the over-large hint is counted "
          "in stats so an operator sees the vendor asked for more than was granted")

    lim.observe(r)
    check("quota headers are recorded but not self-throttled on",
          lim.stats().get("quota_remaining") == 17,
          "reported so an operator can see headroom; not acted on, because a shared "
          "tenant quota falling is not this connector's fault to fix by stopping")

    # retry loop
    SLEEP.reset()
    t = ScriptedTransport([
        (503, {}, b"upstream down"),
        (429, {"retry-after": "7"}, b"slow down"),
        (200, {}, {"ok": True}),
    ])
    client = ApiClient(t, limiter=limiter(),
                       retry=RetryPolicy(attempts=4, backoff_base_s=0.5, jitter=False),
                       name="t", sleep=SLEEP.sleep, seed=1)
    resp = await client.send(Request("GET", "https://api.example.com/x", label="x"))
    check("a retryable status is retried and eventually succeeds",
          resp.status == 200 and client.stats()["retries"] == 2)
    check("a server's own retry-after wins over the computed backoff",
          any(abs(s - 7.0) < 0.01 for s in SLEEP.slept),
          f"slept {[round(s, 2) for s in SLEEP.slept]} — taking max(hint, backoff) rather "
          "than their sum avoids double-counting the same wait")
    check("503 and 429 are both in the retry set, 404 is not",
          503 in RETRY_STATUSES and 429 in RETRY_STATUSES
          and 404 not in RETRY_STATUSES and 400 not in RETRY_STATUSES)

    t = ScriptedTransport([(401, {}, {"error": {"code": "InvalidAuthenticationToken",
                                                "message": "Access token has expired"}})])
    client = ApiClient(t, limiter=limiter(),
                       retry=RetryPolicy(attempts=3, jitter=False), sleep=SLEEP.sleep)
    try:
        await client.send(Request("GET", "https://graph.microsoft.com/v1.0/x"))
        check("a 401 raises AuthError immediately, not after four retries", False)
    except AuthError as exc:
        check("a 401 raises AuthError immediately, not after four retries",
              client.stats()["retries"] == 0 and "expired" in str(exc),
              "retrying a wrong secret every cycle trips Entra's smart lockout on the "
              "app itself; and the vendor's own message is carried through")

    for body, want in (
        ({"error": {"code": "Forbidden", "message": "Insufficient privileges"}},
         "Insufficient privileges"),
        ({"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"},
         "AADSTS7000215"),
        ({"errorSummary": "Invalid session", "errorCode": "E0000005"}, "Invalid session"),
        ({"__type": "AccessDeniedException", "message": "not authorized"},
         "not authorized"),
        ({"errors": [{"code": 403, "message": "access denied"}]}, "access denied"),
    ):
        resp = HttpResponse(status=403, headers={}, body=json.dumps(body).encode())
        check(f"the vendor's own error text is extracted from {list(body)[0]!r}",
              want in _vendor_error(resp))

    # idempotency is declared, not derived
    t = ScriptedTransport([(503, {}, b"x"), (200, {}, {"ok": 1})])
    client = ApiClient(t, limiter=limiter(),
                       retry=RetryPolicy(attempts=3, jitter=False), sleep=SLEEP.sleep)
    resp = await client.send(Request("POST", "https://cloudtrail.us-east-1.amazonaws.com/",
                                     json_body={"MaxResults": 1}, idempotent=True))
    check("a POST the caller declared idempotent is retried",
          resp.status == 200,
          "CloudTrail LookupEvents, GCP entries:list and Defender advancedqueries/run "
          "are all reads expressed as POSTs; deriving retryability from the method "
          "would abandon every one of them on a single 503")

    t = ScriptedTransport([(503, {}, b"x")])
    client = ApiClient(t, limiter=limiter(),
                       retry=RetryPolicy(attempts=3, jitter=False), sleep=SLEEP.sleep)
    try:
        await client.send(Request("POST", "https://api.example.com/disable-user",
                                  json_body={"id": "x"}, idempotent=False))
        check("a non-idempotent POST is not retried", False)
    except (HttpError, TransientError):
        check("a non-idempotent POST is not retried",
              client.stats()["retries"] == 0,
              "and this is why the flag is the caller's to set: retrying a "
              "disable-account call is a different kind of wrong from retrying a read")


# ── 2. auth ─────────────────────────────────────────────────────────────────


async def test_auth_basics():
    print("\n[auth] credential gating, header schemes, token refresh")

    ok, missing = cred("okta_token", "abc"), cred("okta_domain", "")
    try:
        require(ok, missing)
        check("require() names every unset slot and its env var", False)
    except CredentialsIncomplete as exc:
        check("require() names every unset slot and its env var",
              "OKTA_DOMAIN" in str(exc) and "okta_token" in str(exc),
              "and says what IS set, so 'partly configured' is diagnosable rather "
              "than looking like a permission problem")

    req = Request("GET", "https://x.okta.com/api/v1/logs")
    signed = await StaticHeaderAuth(ok, scheme="SSWS").apply(req)
    check("Okta gets SSWS, not Bearer",
          signed.headers["Authorization"] == "SSWS abc",
          "an Okta API token presented as Bearer 401s with no text that hints why")
    check("...and the original request is not mutated",
          "Authorization" not in req.headers,
          "the retry loop re-authorises the same Request object on every attempt; "
          "mutating it accumulates a stale x-amz-date and a dead signature")

    tok = Token(value="t", expires_at=1000.0, scope="")
    check("a token inside the refresh margin is not usable",
          tok.usable(1000.0 - REFRESH_MARGIN_SECONDS - 1, REFRESH_MARGIN_SECONDS)
          and not tok.usable(1000.0 - REFRESH_MARGIN_SECONDS + 1,
                             REFRESH_MARGIN_SECONDS),
          f"the margin is {REFRESH_MARGIN_SECONDS:.0f}s, so a token never expires "
          "mid-request")

    # single-flight refresh
    mints = []

    def mint(request):
        mints.append(request)
        return (200, {}, {"access_token": f"tok{len(mints)}", "expires_in": 3600,
                          "token_type": "Bearer"})

    clock = Clock()
    t = ScriptedTransport([mint] * 10)
    client = ApiClient(t, limiter=limiter(),
                       sleep=SLEEP.sleep)
    auth = OAuth2ClientCredentials(
        client, token_url="https://login.microsoftonline.com/tid/oauth2/v2.0/token",
        client_id=cred("cid", "id"), client_secret=cred("secret", "s"),
        scope="https://graph.microsoft.com/.default", clock=clock,
    )
    reqs = [Request("GET", f"https://graph.microsoft.com/v1.0/x?{i}") for i in range(8)]
    out = await asyncio.gather(*(auth.apply(r) for r in reqs))
    check("eight concurrent requests mint one token, not eight",
          len(mints) == 1 and all(r.headers["Authorization"] == "Bearer tok1" for r in out),
          "a mid-backfill expiry otherwise produces a burst of identical token "
          "requests, which Entra throttles at tenant level — locking the app out of "
          "authentication entirely, not just out of this API")

    clock.advance(3600)
    await auth.apply(Request("GET", "https://graph.microsoft.com/v1.0/y"))
    check("an expired token is minted again", len(mints) == 2)

    sent = dict(mints[0].form_body or {})
    check("the token request is a form body with grant_type=client_credentials",
          sent.get("grant_type") == "client_credentials"
          and sent.get("scope") == "https://graph.microsoft.com/.default",
          str(sorted(sent)))

    t2 = ScriptedTransport([(200, {}, {"token_type": "Bearer", "expires_in": 3600})])
    c2 = ApiClient(t2, limiter=limiter(), sleep=SLEEP.sleep)
    a2 = OAuth2ClientCredentials(c2, token_url="https://x/token",
                                 client_id=cred("cid", "i"),
                                 client_secret=cred("s", "s"), clock=Clock())
    try:
        await a2.apply(Request("GET", "https://api.example.com/x"))
        check("a token response with no access_token names the keys it did return",
              False)
    except AuthError as exc:
        check("a token response with no access_token names the keys it did return",
              "token_type" in str(exc) and "expires_in" in str(exc),
              "a 200 with no token is what a wrong token_url returns; the key list is "
              "what distinguishes that from a wrong secret")

    unset = OAuth2ClientCredentials(
        client, token_url="https://x/token", client_id=cred("cid", ""),
        client_secret=cred("secret", ""), clock=Clock())
    try:
        await unset.apply(Request("GET", "https://api.example.com/x"))
        check("an unconfigured authorizer refuses before making a request", False)
    except CredentialsIncomplete:
        check("an unconfigured authorizer refuses before making a request", True)


# ── 3. service accounts ─────────────────────────────────────────────────────

_TEST_KEY = None


def _keypair():
    global _TEST_KEY
    if _TEST_KEY is None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        _TEST_KEY = (key, pem)
    return _TEST_KEY


async def test_service_account(tmp: Path):
    print("\n[auth] Google service accounts and RS256 JWTs")

    key, pem = _keypair()
    doc = {"type": "service_account", "client_email": "svc@p.iam.gserviceaccount.com",
           "private_key": pem, "token_uri": "https://oauth2.googleapis.com/token",
           "project_id": "my-project"}

    sa = ServiceAccount.parse(json.dumps(doc))
    check("inline JSON parses", sa.client_email == "svc@p.iam.gserviceaccount.com"
          and sa.project_id == "my-project")

    path = tmp / "sa.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    sa2 = ServiceAccount.parse(str(path))
    check("a filesystem path parses too",
          sa2.client_email == sa.client_email,
          "GOOGLE_APPLICATION_CREDENTIALS is conventionally a path, but container "
          "deployments inline the JSON into the variable; accepting only one of the "
          "two fails for half of all real deployments")

    escaped = dict(doc, private_key=pem.replace("\n", "\\n"))
    sa3 = ServiceAccount.parse(json.dumps(escaped))
    check("a PEM whose newlines survived as literal backslash-n is repaired",
          sa3.private_key.count("\n") > 5,
          "which is what happens to every service-account key pasted into a .env "
          "file or a CI secret box")

    claims = {"iss": sa.client_email, "scope": "https://x/scope",
              "aud": sa.token_uri, "iat": 1_800_000_000, "exp": 1_800_003_600}
    jwt = sa.sign_jwt(claims)
    header_b64, payload_b64, sig_b64 = jwt.split(".")

    def unb64(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    header = json.loads(unb64(header_b64))
    check("the JWT header is RS256", header == {"alg": "RS256", "typ": "JWT"},
          str(header))
    check("the claims round-trip", json.loads(unb64(payload_b64)) == claims)

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as apad
    try:
        key.public_key().verify(
            unb64(sig_b64), f"{header_b64}.{payload_b64}".encode(),
            apad.PKCS1v15(), hashes.SHA256())
        verified = True
    except InvalidSignature:
        verified = False
    check("the signature verifies against the public key",
          verified,
          "checked with cryptography's verifier rather than by re-signing, so this "
          "is a real check and not the signer agreeing with itself")

    tampered = f"{header_b64}.{payload_b64}x.{sig_b64}"
    h2, p2, s2 = tampered.split(".")
    try:
        key.public_key().verify(unb64(s2), f"{h2}.{p2}".encode(),
                                apad.PKCS1v15(), hashes.SHA256())
        caught = False
    except Exception:
        caught = True
    check("...and a tampered payload fails it", caught)

    minted = []

    def mint(request):
        minted.append(request)
        return (200, {}, {"access_token": "ya29.x", "expires_in": 3599,
                          "token_type": "Bearer"})

    t = ScriptedTransport([mint])
    client = ApiClient(t, limiter=limiter(),
                       sleep=SLEEP.sleep)
    auth = ServiceAccountJwtAuth(
        client, credentials_json=cred("gcp_sa", json.dumps(doc)),
        scopes=("https://www.googleapis.com/auth/logging.read",),
        clock=Clock())
    out = await auth.apply(Request("GET", "https://logging.googleapis.com/v2/x"))
    check("the JWT-bearer grant exchanges an assertion for an access token",
          out.headers["Authorization"] == "Bearer ya29.x"
          and dict(minted[0].form_body or {}).get("grant_type")
          == "urn:ietf:params:oauth:grant-type:jwt-bearer")
    assertion = dict(minted[0].form_body or {})["assertion"]
    sent_claims = json.loads(unb64(assertion.split(".")[1]))
    check("GCP sends no `sub`", "sub" not in sent_claims, str(sorted(sent_claims)))

    minted.clear()
    t = ScriptedTransport([mint])
    client = ApiClient(t, limiter=limiter(),
                       sleep=SLEEP.sleep)
    auth = ServiceAccountJwtAuth(
        client, credentials_json=cred("gws_sa", json.dumps(doc)),
        scopes=("https://www.googleapis.com/auth/admin.reports.audit.readonly",),
        subject=cred("gws_admin", "admin@example.com", "GWS_DELEGATED_ADMIN"),
        clock=Clock())
    await auth.apply(Request("GET", "https://admin.googleapis.com/x"))
    sent_claims = json.loads(unb64(dict(minted[0].form_body or {})["assertion"]
                                   .split(".")[1]))
    check("Workspace sends `sub` — domain-wide delegation is the whole difference "
          "between the two Google connectors",
          sent_claims.get("sub") == "admin@example.com")
    check("...and the delegated admin is a named credential slot, not a bare string, "
          "so probe() can report it as unconfigured",
          isinstance(auth.subject, Credential)
          and auth.subject.env_var == "GWS_DELEGATED_ADMIN")
    check("the assertion's lifetime is the hour Google permits",
          sent_claims["exp"] - sent_claims["iat"] == JWT_LIFETIME_SECONDS,
          str(JWT_LIFETIME_SECONDS))

    for err, hint in (("unauthorized_client", "admin console"),
                      ("invalid_grant", "clock")):
        t = ScriptedTransport([(400, {}, {"error": err, "error_description": "no"})])
        c = ApiClient(t, limiter=limiter(),
                      sleep=SLEEP.sleep)
        a = ServiceAccountJwtAuth(c, credentials_json=cred("sa", json.dumps(doc)),
                                  scopes=("https://x/s",), clock=Clock())
        try:
            await a.apply(Request("GET", "https://x/y"))
            check(f"{err} carries a targeted hint", False)
        except AuthError as exc:
            check(f"{err} carries a targeted hint", hint in str(exc).lower(),
                  str(exc)[:150])

    bad = dict(doc, private_key="-----BEGIN PRIVATE KEY-----\nnope\n"
                                "-----END PRIVATE KEY-----\n")
    try:
        ServiceAccount.parse(json.dumps(bad))
        check("an unparseable private key fails at parse, not at the first request",
              False)
    except CredentialsIncomplete as exc:
        check("an unparseable private key fails at parse, not at the first request",
              "BEGIN PRIVATE KEY" in str(exc),
              "so a mistyped credential surfaces while the operator is setting it up, "
              "rather than as a cycle failure hours later")


# ── 4. SigV4, pinned against botocore and against AWS's published constant ──


async def test_sigv4():
    print("\n[auth] SigV4 — pinned to outside authority, not to itself")

    # AWS publishes this exact derivation in its signing documentation:
    # secret wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, 20150830, us-east-1, iam.
    AWS_DOC_SIGNING_KEY = (
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    )
    SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    got = sigv4_signing_key(SK, "20150830", "us-east-1", "iam").hex()
    check("the four-round signing-key chain matches the constant AWS publishes",
          got == AWS_DOC_SIGNING_KEY,
          got if got != AWS_DOC_SIGNING_KEY else "AWS4->date->region->service->aws4_request")

    check("a space encodes as %20, never as +",
          _uri_encode("b b") == "b%20b",
          "AWS's spec is explicit: the space is reserved and must be %20 'and not "
          "as +'. urllib's urlencode defaults to quote_plus and gets this wrong")
    check("the unreserved set is left alone",
          _uri_encode("A-Za-z0-9-._~") == "A-Za-z0-9-._~")
    check("a slash is encoded in a query value but not in a path",
          _uri_encode("a/b") == "a%2Fb" and _uri_encode("a/b", keep_slash=True) == "a/b",
          "getting this backwards breaks only requests whose params contain a slash — "
          "which is every ARN-filtered CloudTrail lookup, and nothing else")
    check("a hex escape is uppercase",
          _uri_encode(":") == "%3A", "AWS's spec requires uppercase hex")

    AK = "AKIDEXAMPLE"
    cases = [
        ("get-vanilla", "GET", "https://example.amazonaws.com/", "service",
         "us-east-1", None, None),
        ("get-with-path", "GET", "https://example.amazonaws.com/foo/bar", "service",
         "us-east-1", None, None),
        ("get-unreserved-path", "GET", "https://example.amazonaws.com/a~b.c_d-e",
         "service", "us-east-1", None, None),
        ("get-params-needing-sort-and-escape", "GET", "https://example.amazonaws.com/",
         "service", "us-east-1",
         {"Zulu": "a", "alpha": "b b", "arn": "arn:aws:iam::1/role"}, None),
        ("get-empty-param-value", "GET", "https://example.amazonaws.com/", "service",
         "us-east-1", {"acl": ""}, None),
        ("post-json-cloudtrail", "POST",
         "https://cloudtrail.us-east-1.amazonaws.com/", "cloudtrail", "us-east-1",
         None, {"MaxResults": 50, "StartTime": "2026-01-01T00:00:00Z"}),
    ]

    try:
        from botocore.auth import SigV4Auth as BotoSigV4
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
    except ImportError:
        check("SigV4 is compared against botocore across every request shape", False,
              "botocore is NOT INSTALLED, so the only pin left is the signing-key "
              "constant above — install it with `pip install botocore` to restore "
              "this check. Reported as a failure rather than skipped, because a "
              "silently-skipped cross-check is how an unverified signer ships")
        return

    async def sign_mine(method, url, service, region, epoch, params, body):
        auth = SigV4Auth(access_key_id=cred("ak", AK),
                         secret_access_key=cred("sk", SK),
                         region=region, service=service, clock=lambda: epoch)
        req = Request(method=method, url=url, params=params, json_body=body)
        return dict((await auth.apply(req)).headers), req

    matched = 0
    for name, method, url, service, region, params, body in cases:
        pre, req = await sign_mine(method, url, service, region, 0.0, params, body)
        # Percent-encode with `quote`, not the default `quote_plus`: botocore signs
        # the query string it is handed verbatim, so building the comparison URL with
        # `+` for a space would make botocore sign a string AWS's own spec forbids and
        # the mismatch would look like a bug here.
        query = urllib.parse.urlencode(
            params, quote_via=urllib.parse.quote, safe="") if params else ""
        full = url + (f"?{query}" if query else "")
        headers = {"x-amz-content-sha256": pre["x-amz-content-sha256"]}
        if body is not None:
            headers["content-type"] = req.content_type()
        ref = AWSRequest(method=method, url=full, data=req.body_bytes(),
                         headers=headers)
        BotoSigV4(Credentials(AK, SK), service, region).add_auth(ref)
        ref_headers = dict(ref.headers)
        epoch = float(calendar.timegm(
            time.strptime(ref_headers["X-Amz-Date"], "%Y%m%dT%H%M%SZ")))
        ours, _ = await sign_mine(method, url, service, region, epoch, params, body)
        same = ours.get("Authorization") == ref_headers.get("Authorization")
        matched += same
        if not same:
            check(f"sigv4 {name}", False,
                  f"ours={ours.get('Authorization')} boto={ref_headers.get('Authorization')}")

    check("SigV4 is byte-identical to botocore across every request shape",
          matched == len(cases),
          f"{matched}/{len(cases)}: " + ", ".join(c[0] for c in cases)
          + " — compared against AWS's own production signer, because a hand-rolled "
            "signature that is wrong fails as one SignatureDoesNotMatch that reads "
            "exactly like a wrong secret key")

    st = SigV4Auth(access_key_id=cred("ak", AK), secret_access_key=cred("sk", SK),
                   region="us-east-1", service="cloudtrail",
                   session_token=cred("tok", "FQoGZXIvYXdzEXAMPLE"),
                   clock=lambda: 1_800_000_000.0)
    out = await st.apply(Request("POST", "https://cloudtrail.us-east-1.amazonaws.com/",
                                 json_body={"MaxResults": 1}))
    check("a session token is both sent and signed",
          out.headers.get("x-amz-security-token") == "FQoGZXIvYXdzEXAMPLE"
          and "x-amz-security-token" in out.headers["Authorization"],
          "STS credentials fail with an unhelpful 403 if the token is sent but left "
          "out of SignedHeaders")

    r1 = Request("POST", "https://cloudtrail.us-east-1.amazonaws.com/",
                 json_body={"MaxResults": 1})
    a = SigV4Auth(access_key_id=cred("ak", AK), secret_access_key=cred("sk", SK),
                  region="us-east-1", clock=lambda: 1_800_000_000.0)
    s1 = await a.apply(r1)
    b = SigV4Auth(access_key_id=cred("ak", AK), secret_access_key=cred("sk", SK),
                  region="us-east-1", clock=lambda: 1_800_000_600.0)
    s2 = await b.apply(r1)
    check("re-signing the same Request ten minutes later yields a different "
          "signature and a fresh date, and leaves no residue from the first",
          s1.headers["Authorization"] != s2.headers["Authorization"]
          and s1.headers["x-amz-date"] != s2.headers["x-amz-date"]
          and "Authorization" not in r1.headers and "x-amz-date" not in r1.headers,
          "this is why the retry loop re-authorises on every attempt: replaying a "
          "stale x-amz-date yields SignatureDoesNotMatch, which reads like a wrong key")


# ── 5. payload helpers ──────────────────────────────────────────────────────


def test_helpers():
    print("\n[base] timestamps, dotted lookup, the not-an-IP problem")

    check("iso8601 renders the Z form every one of these APIs accepts",
          iso8601(1_800_000_000.0) == "2027-01-15T08:00:00Z",
          iso8601(1_800_000_000.0))

    base = 1_800_000_000.0
    for label, text in (
        ("Z-suffixed", "2027-01-15T08:00:00Z"),
        ("offset-suffixed", "2027-01-15T08:00:00+00:00"),
        ("three fractional digits", "2027-01-15T08:00:00.000Z"),
        ("six fractional digits", "2027-01-15T08:00:00.000000Z"),
        ("seven fractional digits (.NET ticks)", "2027-01-15T08:00:00.0000000Z"),
        ("no zone at all", "2027-01-15T08:00:00"),
    ):
        got = parse_iso8601(text)
        check(f"a timestamp parses: {label}",
              got is not None and abs(got - base) < 1.0,
              f"{text} -> {got}")
    check("a bare epoch parses, because CloudTrail's EventTime is one",
          parse_iso8601(1_800_000_000) == base
          and parse_iso8601("1800000000") == base)
    check("an unparseable timestamp is None, not an exception",
          parse_iso8601("last Tuesday") is None and parse_iso8601("") is None
          and parse_iso8601(None) is None,
          "a raised exception in a normaliser drops the whole batch over one field")
    check("a zone-less timestamp is read as UTC, not as local",
          abs(parse_iso8601("2027-01-15T08:00:00") - base) < 1.0,
          "assuming local would shift every event on this host by 5.5 hours and "
          "break correlation without breaking anything visible")

    doc = {"status": {"errorCode": 50126}, "list": [{"n": "a"}, {"n": "b"}],
           "empty": "", "zero": 0}
    check("dotted lookup reaches nested values", dig(doc, "status.errorCode") == 50126)
    check("...and list indices", dig(doc, "list.1.n") == "b")
    check("a missing path is the default, not a KeyError",
          dig(doc, "a.b.c", "fallback") == "fallback"
          and dig(doc, "status.nope") is None)
    check("first() skips empty but keeps a legitimate zero",
          first(doc, "empty", "status.errorCode") == 50126
          and first(doc, "zero", "status.errorCode") == 0,
          "empty-string, empty-list and empty-dict are skipped; 0 and False are "
          "returned, because a zero error code, a zero byte count and a false "
          "`isInteractive` are all real values a vendor sends and a falsy test would "
          "silently fall through to the next path")

    p = {}
    set_ip(p, "src_endpoint_ip", "203.0.113.9")
    check("a real IP lands in the IP field", p.get("src_endpoint_ip") == "203.0.113.9")
    p = {}
    set_ip(p, "src_endpoint_ip", "cloudformation.amazonaws.com")
    check("AWS's service-principal sourceIPAddress goes to unmapped, not to the IP field",
          "src_endpoint_ip" not in p
          and p["unmapped"]["src_endpoint_ip_raw"] == "cloudformation.amazonaws.com",
          "the Event model validates IP fields strictly because that value reaches "
          "netsh; an unvalidated assignment rejects the whole event and loses a real "
          "management-plane action over a field that was never an address")
    for sentinel in ("private", "gce-internal-ip", "-", "unknown"):
        p = {}
        set_ip(p, "src_endpoint_ip", sentinel)
        check(f"GCP's {sentinel!r} callerIp is not treated as an address",
              "src_endpoint_ip" not in p and p["unmapped"])
    p = {}
    set_ip(p, "src_endpoint_ip", "2001:db8::1")
    check("IPv6 still passes", p.get("src_endpoint_ip") == "2001:db8::1")
    p = {}
    set_ip(p, "src_endpoint_ip", None)
    set_ip(p, "src_endpoint_ip", "")
    check("absent is absent — no empty-string IP", p == {})

    check("records come from whichever key the vendor uses",
          normalise_records({"value": [{"a": 1}]}, "value", "items") == [{"a": 1}]
          and normalise_records({"items": [{"b": 2}]}, "value", "items") == [{"b": 2}]
          and normalise_records({"Events": [{"c": 3}]}, "value") == [])
    check("a 200 carrying an error object instead of an array yields no records "
          "rather than a KeyError",
          normalise_records({"error": {"code": "x"}}, "value") == [],
          "some of these APIs return 200-with-error when a token expires "
          "mid-pagination; '0 records, no next page' is diagnosable, a KeyError "
          "inside a normaliser is counted as a generic cycle failure")
    check("non-dict entries in a record array are dropped",
          normalise_records({"value": [{"a": 1}, "junk", None]}, "value") == [{"a": 1}])


# ── 6. windows ──────────────────────────────────────────────────────────────


def test_windows():
    print("\n[base] window planning — the cursor must not outrun the vendor's index")

    now = 1_800_000_000.0
    p = WindowPlanner(initial_lookback_seconds=86_400, overlap_seconds=120,
                      max_window_seconds=3600, indexing_lag_seconds=0)
    w = p.plan(None, now)
    check("the first run reaches back its initial lookback",
          abs(w.start - (now - 86_400)) < 1.0)
    check("...and is capped at one window wide, flagged as catching up",
          abs(w.seconds - 3600) < 1.0 and w.catching_up,
          "a day of history asked for in one query 504s on Graph and silently caps "
          "on Okta; the flag is what makes the backlog drain at full rate instead of "
          "one window per cadence")

    w = p.plan(now - 600, now)
    check("a subsequent window starts at the cursor minus the overlap",
          abs(w.start - (now - 720)) < 1.0 and abs(w.end - now) < 1.0
          and not w.catching_up)

    lag = WindowPlanner(overlap_seconds=120, max_window_seconds=3600,
                        indexing_lag_seconds=300)
    w = lag.plan(now - 600, now)
    cursor = lag.advance(w, latest_record=None, cursor=now - 600)
    check("with no records the cursor advances only to window_end minus the "
          "indexing lag",
          abs(cursor - (now - 300)) < 1.0,
          "a quiet tenant still makes progress, and the cursor stays behind real "
          "time by the vendor's own delay so a late-indexed record is still inside "
          "the next window. Advancing to `now` is the bug that loses every Entra "
          "sign-in that took twenty minutes to appear")
    check("...and never goes backwards",
          lag.advance(w, latest_record=None, cursor=now) >= now,
          "a cursor that regresses re-reads history forever")
    ahead = lag.advance(w, latest_record=now - 60, cursor=now - 600)
    check("a record later than the floor pulls the cursor forward to it",
          abs(ahead - (now - 60)) < 1.0)

    stalled = WindowPlanner(overlap_seconds=0, max_window_seconds=1800,
                           indexing_lag_seconds=1800)
    w = stalled.plan(now - 600, now)
    check("a lag as wide as the window holds the cursor still rather than skipping "
          "the un-indexed region",
          abs(stalled.advance(w, None, now - 600) - (now - 600)) < 1.0,
          "asserted because it looks like a stall and is not: a source whose "
          "indexing lag is 30 min cannot have its cursor moved into the last 30 min "
          "without losing whatever lands there. It resumes the moment a record with "
          "a real timestamp arrives, and a configuration where lag >= max_window is "
          "a configuration to question, not a bug to code around")

    zero = WindowPlanner(initial_lookback_seconds=0, overlap_seconds=0,
                         max_window_seconds=3600, indexing_lag_seconds=0)
    w = zero.plan(None, now)
    check("a zero-width window is legal and does not go negative",
          w.seconds >= 0 and w.start <= w.end)

    narrow = WindowPlanner(max_window_seconds=3600, min_window_seconds=30)
    first_w = narrow.plan(now - 7200, now).seconds
    narrow.narrow()
    second = narrow.plan(now - 7200, now)
    check("a suspected truncation halves the next window",
          abs(second.seconds - first_w / 2) < 1.0 and second.narrowed,
          f"{first_w:.0f}s -> {second.seconds:.0f}s — re-issuing the same width and "
          "expecting a different answer is not a recovery strategy")
    for _ in range(12):
        narrow.narrow()
    check("...but not below the floor",
          narrow.plan(now - 7200, now).seconds >= 30 - 0.001)
    narrow.widen()
    check("a clean cycle restores the full width",
          abs(narrow.plan(now - 7200, now).seconds - first_w) < 1.0)

    s, e = TimeWindow(start=now, end=now + 60).iso()
    check("a window renders as two Z-form timestamps for a $filter",
          s.endswith("Z") and e.endswith("Z") and s < e, f"{s} -> {e}")


# ── 7. checkpoints ──────────────────────────────────────────────────────────


class BrokenStore:
    """A doc store that is up for reads and down for writes. A real failure mode."""

    def __init__(self):
        self.docs = {}
        self.fail_writes = False

    async def get(self, collection, key):
        return self.docs.get((collection, key))

    async def put(self, collection, doc):
        if self.fail_writes:
            raise ConnectionError("veddb: connection reset by peer")
        self.docs[(collection, doc["id"])] = doc
        return doc


async def test_checkpoints():
    print("\n[base] cursors survive restarts, and a store blip does not reset them")

    m = MemoryCheckpoints()
    await m.save("okta", {"cursor": 123.0, "opaque_cursor": "after=1,2,3"})
    check("memory checkpoints round-trip",
          (await m.load("okta"))["opaque_cursor"] == "after=1,2,3")
    check("an unknown name loads empty rather than raising",
          await m.load("nope") == {})

    store = BrokenStore()
    cp = DocStoreCheckpoints(store)
    await cp.save("entra_signin", {"cursor": 1_800_000_000.0})
    fresh = DocStoreCheckpoints(store)
    check("a cursor written by one process is read by the next",
          (await fresh.load("entra_signin"))["cursor"] == 1_800_000_000.0,
          "without this a restart re-reads the entire initial lookback, which is a "
          "duplicate storm — or a gap, when the restart outlasts the lookback")

    store.fail_writes = True
    await cp.save("entra_signin", {"cursor": 1_800_003_600.0})
    check("a failed save is counted, not raised",
          cp.save_failures == 1 and "connection reset" in cp.last_error,
          "losing a cursor write is a durability problem for the next process, not "
          "a reason to stop collecting in this one")
    check("...and the in-process cursor still advances",
          (await cp.load("entra_signin"))["cursor"] == 1_800_003_600.0,
          "the write-through cache is not an optimisation: without it a five-second "
          "VedDB blip makes the next cycle fall back to the initial lookback and "
          "re-ingest a day of events")

    store.fail_writes = False
    await cp.save("entra_signin", {"cursor": 1_800_007_200.0})
    check("recovery persists again",
          (await DocStoreCheckpoints(store).load("entra_signin"))["cursor"]
          == 1_800_007_200.0)

    class DeadStore:
        async def get(self, *a):
            raise ConnectionError("down")

        async def put(self, *a):
            raise ConnectionError("down")

    dead = DocStoreCheckpoints(DeadStore())
    check("a store that is down for reads yields an empty cursor, not a crash "
          "at startup",
          await dead.load("x") == {} and "down" in dead.last_error)


# ── 8. the Connector base, end to end ───────────────────────────────────────


class FakeConnector(Connector):
    name = "fake_vendor"
    description = "a vendor-shaped API, for exercising the base"
    detects = "nothing; it exists to prove the machinery"
    spec = ConnectorSpec(page_size=2, rate_per_second=1000.0, burst=1000,
                         initial_lookback_seconds=3600, overlap_seconds=60,
                         max_window_seconds=1800, indexing_lag_seconds=300,
                         max_pages_per_cycle=5,
                         docs_url="https://example.test/docs",
                         required_grants=("AuditLog.Read.All",))

    def __init__(self, *a, creds=None, **kw):
        self._creds = creds if creds is not None else (cred("fake_token", "t"),)
        super().__init__(*a, **kw)

    def credentials(self):
        return self._creds

    def authorizer(self):
        return StaticHeaderAuth(self._creds[0]) if self._creds else Authorizer()

    async def fetch_window(self, window):
        out = []
        start_iso, end_iso = window.iso()
        async for page in self.paginate(
            Request("GET", "https://api.vendor.test/events", label="events",
                    params={"since": start_iso, "until": end_iso, "limit": 2}),
            records_at=("value",),
            next_url=lambda resp, body: body.get("@odata.nextLink"),
        ):
            for rec in page:
                self.note_record_time(parse_iso8601(rec.get("time")))
                out.append({"class_uid": 3002, "activity_id": 1,
                            "time": parse_iso8601(rec.get("time")),
                            "metadata_uid": rec.get("id"),
                            "actor_user_name": rec.get("user")})
        return out


class _Pipe:
    """Just enough Pipeline for the base's _submit and fleet-registration paths."""

    class _R:
        def __init__(self, n):
            self.received = n
            self.accepted = n
            self.rejected = 0

    def __init__(self):
        self.got = []
        self.declared = {}

    def declare_source(self, name, **kw):
        self.declared[name] = kw
        return kw

    async def submit(self, source, payloads, agent_id="", keep_events=False):
        self.got.extend(payloads)
        return self._R(len(payloads))


def _rec(i, t):
    return {"id": f"e{i}", "time": t, "user": f"u{i}"}


async def test_connector():
    print("\n[base] the Connector cycle — pagination, cursors, truncation, catch-up")

    clock = Clock()
    pipe = _Pipe()
    T = "2027-01-15T07:50:00Z"
    transport = ScriptedTransport([
        (200, {}, {"value": [_rec(1, T), _rec(2, T)],
                   "@odata.nextLink": "https://api.vendor.test/events?$skiptoken=A"}),
        (200, {}, {"value": [_rec(3, "2027-01-15T07:55:00Z")]}),
    ])
    c = FakeConnector(pipe, None, transport=transport, cadence_seconds=900,
                      clock=clock, sleep=SLEEP.sleep,
                      checkpoints=MemoryCheckpoints())
    n = await c.cycle()
    check("a paginated cycle submits every record from every page",
          n == 3 and len(pipe.got) == 3, f"{n} submitted")
    check("the first request carries this connector's own params",
          "since=" in (urllib.parse.urlencode(dict(transport.seen[0].params or {}))))
    check("a nextLink is followed verbatim, with no params re-applied",
          transport.seen[1].url.endswith("$skiptoken=A")
          and not transport.seen[1].params,
          "Graph's nextLink already contains $filter and $top; re-adding them 400s "
          "with a message about duplicate query options")
    check("the credential reached the wire",
          transport.seen[0].headers.get("Authorization") == "Bearer t")

    cursor_after = c.cursor
    check("the cursor followed the latest record, not the wall clock",
          cursor_after is not None
          and abs(cursor_after - parse_iso8601("2027-01-15T07:55:00Z")) < 1.0,
          f"cursor={iso8601(cursor_after)} vs now={iso8601(clock.now)} — the record "
          "is later than window_end minus the 300 s lag, so it wins")

    saved = await c.checkpoints.load("fake_vendor")
    check("and it was persisted with a human-readable copy",
          saved["cursor"] == cursor_after and saved["cursor_iso"].endswith("Z"))

    # `fetch_window` on its own, with no `poll()` around it. The docstring on
    # `fetch_window` tells every implementation to call `note_record_time`, and the
    # state that call touches used to be created in `poll()` — so a backfill tool, a
    # replay harness or a test driving the documented entry point directly got an
    # AttributeError from following the documentation.
    direct = FakeConnector(
        _Pipe(), None,
        transport=ScriptedTransport([(200, {}, {"value": [_rec(6, T)]})]),
        cadence_seconds=900, clock=Clock(), sleep=SLEEP.sleep,
        checkpoints=MemoryCheckpoints())
    try:
        got = list(await direct.fetch_window(TimeWindow(
            parse_iso8601("2027-01-15T07:00:00Z"), parse_iso8601("2027-01-15T08:00:00Z"))))
        ok, why = len(got) == 1, ""
    except Exception as exc:  # noqa: BLE001
        ok, why = False, f"{type(exc).__name__}: {exc}"
    check("fetch_window works when called on its own, without poll() around it",
          ok and direct._latest_record == parse_iso8601(T), why or f"{direct._latest_record}")

    # truncation: a full page with no next link
    transport = ScriptedTransport([(200, {}, {"value": [_rec(4, T), _rec(5, T)]})])
    c2 = FakeConnector(_Pipe(), None, transport=transport, cadence_seconds=900,
                       clock=Clock(), sleep=SLEEP.sleep, checkpoints=MemoryCheckpoints())
    out = await c2.poll()
    check("a page returning exactly its limit with no cursor is flagged as "
          "suspected truncation",
          c2.suspected_truncations == 1,
          "exactly `limit` records and no next link is indistinguishable from a "
          "complete result unless you check — and a green dashboard over a window "
          "that returned 1000 of its 4000 records is worse than an outage")
    check("...the operator is told in the event stream, not just in a counter",
          any("suspected truncation" in note
              for p in out for note in p.get("notes", [])),
          str([n for p in out for n in p.get("notes", [])])[:160])
    check("...and the next window is narrowed rather than re-issued at the same width",
          c2.planner.plan(c2.cursor, c2.clock()).narrowed)

    # self-referential next link
    loop_url = "https://api.vendor.test/events?$skiptoken=SAME"
    transport = ScriptedTransport([
        (200, {}, {"value": [_rec(6, T)], "@odata.nextLink": loop_url}),
        (200, {}, {"value": [_rec(7, T)], "@odata.nextLink": loop_url}),
    ])
    c3 = FakeConnector(_Pipe(), None, transport=transport, cadence_seconds=900,
                       clock=Clock(), sleep=SLEEP.sleep, checkpoints=MemoryCheckpoints())
    await c3.poll()
    check("a next link that repeats itself stops the cycle and says so",
          "already followed" in c3.stats.last_error and c3.pages == 2,
          "bounded in pages but unbounded in quota, and the symptom — the same 1000 "
          "records re-read every cycle — looks like a healthy source")

    # page ceiling
    pages = [(200, {}, {"value": [_rec(i, T)],
                        "@odata.nextLink": f"https://api.vendor.test/events?p={i + 1}"})
             for i in range(6)]
    transport = ScriptedTransport(pages)
    c4 = FakeConnector(_Pipe(), None, transport=transport, cadence_seconds=900,
                       clock=Clock(), sleep=SLEEP.sleep, checkpoints=MemoryCheckpoints())
    await c4.poll()
    check("the page ceiling stops the cycle and reports the pending remainder",
          c4.page_cap_hits == 1 and c4.pages == 5
          and "ceiling" in c4.stats.last_error,
          f"stopped at {c4.pages} of an unbounded stream; the rest is read next "
          "cycle, not lost")

    # catch-up bypasses the cadence
    clock = Clock()
    transport = ScriptedTransport([(200, {}, {"value": []})] * 4)
    c5 = FakeConnector(_Pipe(), None, transport=transport, cadence_seconds=900,
                       clock=clock, sleep=SLEEP.sleep, checkpoints=MemoryCheckpoints())
    await c5.poll()
    check("a connector reaching back beyond one window knows it is behind",
          c5.catching_up,
          "initial lookback 3600 s, max window 1800 s")
    check("...and returns a zero delay so the backlog drains at full rate",
          c5.next_delay() == 0.0,
          "at a 900 s cadence an hour of downtime otherwise takes fifteen hours to "
          "clear, while the source reports healthy because it genuinely is "
          "collecting — just fifteen hours behind")
    c5.catching_up = False
    check("once current it sleeps its cadence again",
          c5.next_delay() == 900.0)
    c5.catching_up = True
    c5.stats.consecutive_failures = 3
    check("but a failing connector backs off even while behind",
          c5.next_delay() > 0.0,
          "otherwise a broken connector that thinks it is catching up becomes a "
          "tight retry loop against someone else's API")

    check("connector stats report the cursor, the window and the HTTP counters "
          "together",
          {"cursor", "windows", "pages", "records", "requests"}
          <= set(c.stats_extra()),
          str(sorted(c.stats_extra()))[:200])


# ── 9. probe states and the fleet report ────────────────────────────────────


async def test_probe_and_fleet():
    print("\n[base] configured, PARTLY configured, and not configured")

    pipe = _Pipe()
    ok = FakeConnector(pipe, None, creds=(cred("a", "x"), cred("b", "y")),
                       transport=ScriptedTransport([]), clock=Clock(), sleep=SLEEP.sleep)
    av = ok.probe()
    check("fully configured is available, with the required grants as a limitation",
          bool(av) and "AuditLog.Read.All" in av.limitation,
          "a valid credential without the grant returns 403, not empty results — so "
          "'available' has to carry the caveat rather than imply nothing is wrong")

    none = FakeConnector(pipe, None, creds=(cred("a", "", "FAKE_A"),
                                            cred("b", "", "FAKE_B")),
                         transport=ScriptedTransport([]), clock=Clock(),
                         sleep=SLEEP.sleep)
    av = none.probe()
    check("unconfigured names every env var to set and what is lost without it",
          not av and "$FAKE_A" in av.reason and "$FAKE_B" in av.reason
          and "example.test/docs" in av.reason)

    part = FakeConnector(pipe, None, creds=(cred("a", "x", "FAKE_A"),
                                            cred("b", "", "FAKE_B")),
                         transport=ScriptedTransport([]), clock=Clock(),
                         sleep=SLEEP.sleep)
    av = part.probe()
    check("PARTLY configured is called out as worse than unconfigured",
          not av and "PARTLY" in av.reason and "$FAKE_B" in av.reason
          and "a" in av.reason,
          "two of three slots set means every call fails as an auth error, which "
          "reads like a permission problem rather than a missing setting")

    fleet = ConnectorFleet(pipe)

    class A(FakeConnector):
        name = "vendor_a"

    class B(FakeConnector):
        name = "vendor_b"

    class C(FakeConnector):
        name = "vendor_c"

    fleet.add(A(pipe, None, creds=(cred("a", "x"),),
                transport=ScriptedTransport([]), clock=Clock(), sleep=SLEEP.sleep))
    fleet.add(B(pipe, None, creds=(cred("a", "", "B_TOK"),),
                transport=ScriptedTransport([]), clock=Clock(), sleep=SLEEP.sleep))
    fleet.add(C(pipe, None, creds=(cred("a", "x", "C_A"), cred("b", "", "C_B")),
                transport=ScriptedTransport([]), clock=Clock(), sleep=SLEEP.sleep))
    report = fleet.report()
    check("the fleet report counts configured, PARTLY configured and awaiting",
          "1 configured" in report and "1 PARTLY configured" in report
          and "1 awaiting credentials" in report, report.splitlines()[-4:][0][:120])
    check("...and says the inert ones are inert, not broken",
          "emulation generator" in report,
          "an operator reading a list of red sources needs to know detection and "
          "response are still being exercised")

    setup = fleet.setup_instructions()
    check("setup instructions list exactly the missing env vars per connector",
          "$B_TOK" in setup and "$C_B" in setup and "MISSING" in setup
          and "$C_A" in setup and "set" in setup,
          "including the ones already set, marked as set, so the operator can see "
          "which half of a partial configuration is done")
    check("...with the grants and the docs URL beside them",
          "AuditLog.Read.All" in setup and "example.test/docs" in setup)
    check("every credential slot is enumerable for the readiness report",
          len(fleet.credential_slots()) == 4,
          str([f"{n}:{c.name}" for n, c in fleet.credential_slots()]))


# ── main ────────────────────────────────────────────────────────────────────


async def main():
    tmp = Path("var/test_connectors")
    tmp.mkdir(parents=True, exist_ok=True)
    print("=" * 74)
    print("ingest.connectors — transport, auth, windows, pagination")
    print("=" * 74)
    await test_http()
    await test_auth_basics()
    await test_service_account(tmp)
    await test_sigv4()
    test_helpers()
    test_windows()
    await test_checkpoints()
    await test_connector()
    await test_probe_and_fleet()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    # Guarded, so that another suite can import the harness in this file
    # (ScriptedTransport, Clock, Sleeper) without running the suite. Unguarded, the
    # `asyncio.run` below fires at import time, and if the importer is itself async it
    # raises "asyncio.run() cannot be called from a running event loop" — a module that
    # cannot be imported forces every other suite to duplicate the fakes.
    sys.exit(asyncio.run(main()))
