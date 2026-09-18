"""Authentication for the API connectors: five handshakes, one interface.

Every connector ends up needing "given a :class:`~ingest.connectors.http.Request`,
return one that is authorised". Nothing else is shared, because the five mechanisms
in use across these ten APIs are genuinely unlike each other:

===========================  ==============================================
Okta                         static ``Authorization: SSWS <token>``
Graph / Defender / M365      OAuth2 client credentials, bearer, ~60 min
CrowdStrike                  OAuth2 client credentials at a different URL,
                             ~30 min, and the token is *also* the rate-limit
                             identity
GCP / Google Workspace       locally RS256-signed JWT exchanged for a bearer,
                             plus ``sub`` impersonation for Workspace
AWS CloudTrail               per-request SigV4 over the body hash and clock
===========================  ==============================================

The last one is why :class:`~ingest.connectors.http.ApiClient` re-authorises on every
retry rather than signing once. A SigV4 signature covers ``x-amz-date`` and the
payload hash and is valid for a few minutes; replaying the first attempt's headers
after a 30-second backoff yields ``SignatureDoesNotMatch``, which reads exactly like
a wrong secret key and sends the operator to rotate a credential that was fine.

── On implementing SigV4 rather than importing boto3 ─────────────────────────
boto3 is 40 MB of dependency, brings its own retry and endpoint-resolution stack that
would fight the one above, and is synchronous — every call would need a thread. The
signing algorithm itself is about sixty lines of HMAC. It is implemented here, and
:mod:`tests.scratch_connectors` pins it two ways rather than one. The signing-key
derivation is asserted against the constant AWS publishes in its signing
documentation, which validates the four-round HMAC chain standalone. Then the whole
``Authorization`` header is compared byte-for-byte with **botocore** — AWS's own
production signer, installed for the test only — across six request shapes:
get-vanilla, a path, an unreserved-character path, a query value containing an ARN's
slashes, an empty parameter value, and CloudTrail's POST-with-JSON-body. That is a
stronger pin than the single published vector originally planned here, and it is worth
the trouble: a signature that is subtly wrong fails as one ``SignatureDoesNotMatch``
whose text reads exactly like a wrong secret key.

One trap the cross-check surfaced, recorded because it will bite anyone who repeats
it: :func:`urllib.parse.urlencode` must not be used to build a URL for comparison. It
defaults to ``quote_plus`` and emits ``+`` for a space, while AWS's specification says
the space "must be encoded as '%20' (and not as '+')". botocore signs the query string
it is handed verbatim, so the harness — not the signer — is what looks broken.

── On tokens and concurrency ─────────────────────────────────────────────────
A connector paginating a backfill issues requests back to back. If the token expires
mid-backfill, every in-flight call independently notices and mints a replacement —
against Entra that is a burst of identical token requests, which is throttled at the
tenant level and can lock the app out of authentication entirely while the data calls
it was protecting still fail. So refresh is serialised behind a lock and the winner's
token is shared, and it happens :data:`REFRESH_MARGIN_SECONDS` *before* expiry rather
than on the 401, because a token that expires between the check and the send is a race
no amount of retrying makes rare.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import quote, urlsplit

from core.config import Credential, MissingCredential
from ingest.connectors.http import ApiClient, AuthError, HttpError, Request

#: Refresh this long before a token actually expires. Entra's tokens are nominally
#: 3600 s; a 300 s margin costs one extra token request per hour and removes the
#: entire class of "expired between the check and the send" failures.
REFRESH_MARGIN_SECONDS = 300.0

#: Assume this lifetime when a token endpoint returns no ``expires_in``. Short on
#: purpose: guessing long means using a dead token, and the cost of guessing short is
#: one extra handshake.
ASSUMED_TOKEN_LIFETIME = 600.0

#: JWT assertion lifetime for the Google handshake. Google rejects assertions with
#: ``exp`` more than one hour out, and clock skew on the *client* is the usual cause
#: of ``invalid_grant`` here, so the window is kept well inside the limit.
JWT_LIFETIME_SECONDS = 3600


class CredentialsIncomplete(RuntimeError):
    """Some but not all of a connector's credential slots were supplied.

    A distinct failure from "not configured", and a much more common one in practice:
    an operator who sets ``ENTRA_TENANT_ID`` and ``ENTRA_CLIENT_ID`` but forgets the
    secret has a connector that looks half-live. Reporting it as merely unconfigured
    hides the fact that someone tried; reporting it as an auth failure blames the
    wrong thing. It gets its own name so the readiness report can say which slot is
    missing out of which set.
    """


def require(*credentials: Credential) -> None:
    """Raise :class:`CredentialsIncomplete` naming every unset slot."""
    missing = [c for c in credentials if not c.configured]
    if not missing:
        return
    have = [c.name for c in credentials if c.configured]
    raise CredentialsIncomplete(
        f"missing {', '.join(c.name for c in missing)} "
        f"(set {', '.join('$' + c.env_var for c in missing)})"
        + (f"; already have {', '.join(have)}" if have else "")
    )


# ── the interface ───────────────────────────────────────────────────────────


class Authorizer:
    """Turns a Request into an authorised Request.

    Subclasses override :meth:`apply`. The base is not abstract because the null
    authorizer — used by the free intel feeds, which need no credential at all — is a
    legitimate implementation and should not need a subclass to say so.
    """

    #: Human-readable, for the readiness report.
    describes: str = "no authentication"

    async def apply(self, request: Request) -> Request:
        return request

    async def __call__(self, request: Request) -> Request:
        return await self.apply(request)

    def stats(self) -> dict[str, Any]:
        return {}


def _with_headers(request: Request, extra: Mapping[str, str]) -> Request:
    """A copy of *request* with headers merged.

    Copied rather than mutated because the retry loop hands the *same* Request object
    to :meth:`Authorizer.apply` on every attempt. Mutating it would accumulate stale
    ``Authorization`` and ``x-amz-date`` headers across attempts — and for SigV4,
    would leave the previous attempt's signature in the set of signed headers, which
    fails in a way that names neither the retry nor the mutation.
    """
    headers = dict(request.headers)
    headers.update(extra)
    return Request(
        method=request.method,
        url=request.url,
        label=request.label,
        params=request.params,
        headers=headers,
        json_body=request.json_body,
        form_body=request.form_body,
        raw_body=request.raw_body,
        idempotent=request.idempotent,
        timeout_s=request.timeout_s,
    )


class StaticHeaderAuth(Authorizer):
    """One fixed header. Okta's ``SSWS`` and the generic SaaS bearer.

    The scheme is a parameter because Okta's is not ``Bearer``: an Okta API token
    presented as ``Bearer`` returns 401 with no useful text, which is a ten-minute
    debugging session the first time and every time.
    """

    def __init__(
        self, token: Credential, *, scheme: str = "Bearer", header: str = "Authorization"
    ) -> None:
        self.token = token
        self.scheme = scheme
        self.header = header
        self.describes = f"{header}: {scheme} <{token.name}>"

    async def apply(self, request: Request) -> Request:
        value = self.token.value  # raises MissingCredential, loudly, by design
        return _with_headers(
            request, {self.header: f"{self.scheme} {value}".strip()}
        )


# ── OAuth2 client credentials ───────────────────────────────────────────────


@dataclass
class Token:
    value: str = field(repr=False, default="")
    expires_at: float = 0.0
    scope: str = ""

    def usable(self, now: float, margin: float = REFRESH_MARGIN_SECONDS) -> bool:
        return bool(self.value) and self.expires_at - margin > now


class OAuth2ClientCredentials(Authorizer):
    """The two-legged OAuth2 flow, as four of these vendors implement it.

    Vendor differences that are *not* abstracted away, because pretending they are
    identical is how one of them silently stops working:

    * **Entra/Defender/M365** want ``scope=<resource>/.default`` and reject the older
      ``resource=`` parameter on the v2.0 endpoint.
    * **CrowdStrike** has no scope at all, wants ``client_id``/``client_secret`` in
      the form body, and returns ``expires_in: 1799``.
    * Entra returns ``ext_expires_in`` as well as ``expires_in``; the shorter is the
      one that matters.

    So the request body is assembled from explicit ``scope``/``extra`` parameters set
    by each connector, and only the caching, the refresh margin and the single-flight
    lock are shared.
    """

    def __init__(
        self,
        client: ApiClient,
        *,
        token_url: str,
        client_id: Credential,
        client_secret: Credential,
        scope: str = "",
        extra: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.time,
        label: str = "oauth2.token",
    ) -> None:
        self.client = client
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.extra = dict(extra or {})
        self.clock = clock
        self.label = label
        self._token = Token()
        self._lock: Any = None
        self.mints = 0
        self.describes = f"OAuth2 client credentials at {urlsplit(token_url).netloc}"

    def _ensure_lock(self) -> Any:
        # Created lazily rather than in __init__ so an Authorizer can be constructed
        # outside a running loop — which is what the readiness report does when it
        # describes a connector it is not going to start.
        if self._lock is None:
            import asyncio

            self._lock = asyncio.Lock()
        return self._lock

    async def token(self) -> str:
        now = self.clock()
        if self._token.usable(now):
            return self._token.value
        async with self._ensure_lock():
            # Re-checked inside the lock: the whole point is that the other N-1
            # waiters use the winner's token rather than each minting their own.
            now = self.clock()
            if self._token.usable(now):
                return self._token.value
            self._token = await self._mint()
            return self._token.value

    async def _mint(self) -> Token:
        require(self.client_id, self.client_secret)
        body = {
            "grant_type": "client_credentials",
            "client_id": self.client_id.value,
            "client_secret": self.client_secret.value,
        }
        if self.scope:
            body["scope"] = self.scope
        body.update(self.extra)
        request = Request(
            "POST",
            self.token_url,
            label=self.label,
            form_body=body,
            # A token request is a read of an authorisation decision and safe to
            # repeat, but it is *not* free: Entra throttles the token endpoint per
            # app, so the retry policy's attempt count is what bounds it.
            idempotent=True,
        )
        resp = await self.client.transport.send(request)
        payload = resp.json()
        if not resp.ok or not isinstance(payload, Mapping):
            raise AuthError(
                f"{self.label}: token request returned HTTP {resp.status}: "
                f"{str(payload)[:300]}",
                status=resp.status,
                url=self.token_url,
            )
        value = payload.get("access_token") or ""
        if not value:
            raise AuthError(
                f"{self.label}: token response carried no access_token "
                f"(keys: {sorted(payload)})",
                status=resp.status,
                url=self.token_url,
            )
        try:
            lifetime = float(payload.get("expires_in") or ASSUMED_TOKEN_LIFETIME)
        except (TypeError, ValueError):
            lifetime = ASSUMED_TOKEN_LIFETIME
        self.mints += 1
        return Token(
            value=str(value),
            expires_at=self.clock() + lifetime,
            scope=str(payload.get("scope") or self.scope),
        )

    async def apply(self, request: Request) -> Request:
        if request.url == self.token_url:
            return request  # minting its own token must not recurse
        return _with_headers(request, {"Authorization": f"Bearer {await self.token()}"})

    def stats(self) -> dict[str, Any]:
        return {
            "token_mints": self.mints,
            "token_expires_in": round(max(0.0, self._token.expires_at - self.clock())),
        }


# ── Google: locally signed JWT → bearer ─────────────────────────────────────


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass(frozen=True)
class ServiceAccount:
    """The fields of a Google service-account key that matter here."""

    client_email: str
    private_key: str = field(repr=False)
    token_uri: str = "https://oauth2.googleapis.com/token"
    project_id: str = ""

    @staticmethod
    def parse(raw: str) -> "ServiceAccount":
        """Accept the JSON itself *or* a path to it.

        Both, because the conventional environment variable is
        ``GOOGLE_APPLICATION_CREDENTIALS`` and Google's own libraries define it as a
        **path**, while a container deployment usually has the JSON inline in a
        secret. Accepting only one of the two guarantees half of all operators hit an
        error that says nothing about which form was expected.
        """
        text = raw.strip()
        if not text:
            raise CredentialsIncomplete("the GCP service-account credential is empty")
        if not text.startswith("{"):
            path = Path(text).expanduser()
            if not path.exists():
                raise CredentialsIncomplete(
                    f"the GCP credential is neither JSON nor an existing file: {text!r}"
                )
            text = path.read_text(encoding="utf-8")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CredentialsIncomplete(
                f"the GCP service-account key is not valid JSON: {exc}"
            ) from exc
        missing = [k for k in ("client_email", "private_key") if not doc.get(k)]
        if missing:
            raise CredentialsIncomplete(
                f"the GCP service-account key is missing {', '.join(missing)}; "
                "this looks like an OAuth client secret rather than a service-account "
                "key (the service-account form has type='service_account')"
            )
        # A JSON-embedded PEM arrives with literal backslash-n whenever a shell, a YAML
        # file or a CI secret box has escaped it — which is most of the time. Repaired
        # here rather than at signing time so the stored value is the real key, and
        # then *loaded* here so a malformed one fails while an operator is setting the
        # credential up. The alternative is OpenSSL's "Could not deserialize key data"
        # arriving from the first collection cycle, hours later, as a cycle failure.
        pem = str(doc["private_key"]).replace("\\n", "\n")
        account = ServiceAccount(
            client_email=str(doc["client_email"]),
            private_key=pem,
            token_uri=str(doc.get("token_uri") or "https://oauth2.googleapis.com/token"),
            project_id=str(doc.get("project_id") or ""),
        )
        account.load_key()
        return account

    def load_key(self) -> Any:
        """Deserialise the PEM, or say why it cannot be. Also the parse-time check."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        try:
            key = serialization.load_pem_private_key(
                self.private_key.encode(), password=None
            )
        except Exception as exc:  # cryptography raises several unrelated types here
            raise CredentialsIncomplete(
                f"the service-account private key could not be read ({exc}); it must "
                "be the full PEM block from the JSON key file, beginning "
                "'-----BEGIN PRIVATE KEY-----'"
            ) from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise CredentialsIncomplete(
                f"the service-account key is {type(key).__name__}, not RSA; Google's "
                "JWT-bearer flow is RS256 only"
            )
        return key

    def sign_jwt(self, claims: Mapping[str, Any]) -> str:
        """RS256-sign a JWT with this key. No PyJWT dependency."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        key = self.load_key()
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        body = _b64url(json.dumps(dict(claims), separators=(",", ":")).encode())
        signing_input = f"{header}.{body}".encode()
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{body}.{_b64url(sig)}"


class ServiceAccountJwtAuth(Authorizer):
    """Google's JWT-bearer flow, with optional domain-wide delegation.

    ``subject`` is what separates the two Google connectors. GCP audit logs are read
    by the service account *as itself*, so there is no ``sub``. Google Workspace
    reports are readable only by a human administrator, so the service account must
    impersonate one — and that requires the ``sub`` claim *and* the client ID to be
    authorised for the exact scope list in the Workspace admin console. A missing
    ``sub`` there returns ``unauthorized_client``, which says nothing about
    impersonation; the error is re-raised here with that sentence attached.
    """

    def __init__(
        self,
        client: ApiClient,
        *,
        credentials_json: Credential,
        scopes: tuple[str, ...],
        subject: Credential | None = None,
        clock: Callable[[], float] = time.time,
        label: str = "google.token",
    ) -> None:
        self.client = client
        self.credentials_json = credentials_json
        self.scopes = scopes
        self.subject = subject
        self.clock = clock
        self.label = label
        self._token = Token()
        self._account: ServiceAccount | None = None
        self._lock: Any = None
        self.mints = 0
        self.describes = (
            "Google service-account JWT"
            + (" with domain-wide delegation" if subject is not None else "")
        )

    def account(self) -> ServiceAccount:
        if self._account is None:
            require(self.credentials_json)
            self._account = ServiceAccount.parse(self.credentials_json.value)
        return self._account

    def _ensure_lock(self) -> Any:
        if self._lock is None:
            import asyncio

            self._lock = asyncio.Lock()
        return self._lock

    async def token(self) -> str:
        if self._token.usable(self.clock()):
            return self._token.value
        async with self._ensure_lock():
            if self._token.usable(self.clock()):
                return self._token.value
            self._token = await self._mint()
            return self._token.value

    async def _mint(self) -> Token:
        acct = self.account()
        now = int(self.clock())
        claims: dict[str, Any] = {
            "iss": acct.client_email,
            "scope": " ".join(self.scopes),
            "aud": acct.token_uri,
            "iat": now,
            "exp": now + JWT_LIFETIME_SECONDS,
        }
        if self.subject is not None:
            require(self.subject)
            claims["sub"] = self.subject.value
        assertion = acct.sign_jwt(claims)
        resp = await self.client.transport.send(
            Request(
                "POST",
                acct.token_uri,
                label=self.label,
                form_body={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
            )
        )
        payload = resp.json()
        if not resp.ok or not isinstance(payload, Mapping):
            hint = ""
            if isinstance(payload, Mapping) and payload.get("error") == "unauthorized_client":
                hint = (
                    " — 'unauthorized_client' from this endpoint almost always means "
                    "the service account's client ID has not been granted these exact "
                    "scopes in the Workspace admin console (Security → API controls → "
                    "Domain-wide delegation), or the 'sub' address is not a real admin."
                )
            elif isinstance(payload, Mapping) and payload.get("error") == "invalid_grant":
                hint = (
                    " — 'invalid_grant' here is usually client clock skew: the JWT's "
                    "iat/exp are signed locally and Google rejects them if this host's "
                    "clock is more than a few minutes off."
                )
            raise AuthError(
                f"{self.label}: HTTP {resp.status}: {str(payload)[:300]}{hint}",
                status=resp.status,
                url=acct.token_uri,
            )
        value = str(payload.get("access_token") or "")
        if not value:
            raise AuthError(f"{self.label}: no access_token in response", url=acct.token_uri)
        try:
            lifetime = float(payload.get("expires_in") or ASSUMED_TOKEN_LIFETIME)
        except (TypeError, ValueError):
            lifetime = ASSUMED_TOKEN_LIFETIME
        self.mints += 1
        return Token(value=value, expires_at=self.clock() + lifetime)

    async def apply(self, request: Request) -> Request:
        if self._account is not None and request.url == self._account.token_uri:
            return request
        return _with_headers(request, {"Authorization": f"Bearer {await self.token()}"})

    def stats(self) -> dict[str, Any]:
        return {
            "token_mints": self.mints,
            "token_expires_in": round(max(0.0, self._token.expires_at - self.clock())),
        }


# ── AWS Signature Version 4 ─────────────────────────────────────────────────

_UNRESERVED_SAFE = "-_.~"


def _uri_encode(value: str, *, keep_slash: bool = False) -> str:
    """RFC 3986 percent-encoding as SigV4 defines it.

    ``quote`` with an explicit safe set rather than the default, because Python's
    default treats ``/`` as safe everywhere. In a canonical *query string* a ``/``
    must be encoded, and in a canonical *URI path* it must not — one function, two
    call sites, and getting it backwards produces ``SignatureDoesNotMatch`` only for
    the requests whose parameters happen to contain a slash. Which, for a CloudTrail
    lookup filtered on an ARN, is all of them.
    """
    return quote(value, safe=_UNRESERVED_SAFE + ("/" if keep_slash else ""))


def sigv4_canonical_request(
    request: Request, *, headers: Mapping[str, str], payload_hash: str
) -> tuple[str, str]:
    """The canonical request and its signed-header list."""
    parts = urlsplit(request.url)
    path = parts.path or "/"
    canonical_path = "/".join(_uri_encode(seg) for seg in path.split("/")) or "/"
    query_pairs: list[tuple[str, str]] = []
    if parts.query:
        for chunk in parts.query.split("&"):
            if not chunk:
                continue
            name, _, value = chunk.partition("=")
            query_pairs.append((name, value))
    for name, value in (request.params or {}).items():
        query_pairs.append((str(name), "" if value is None else str(value)))
    canonical_query = "&".join(
        f"{_uri_encode(n)}={_uri_encode(v)}"
        for n, v in sorted(query_pairs, key=lambda p: (p[0], p[1]))
    )
    folded = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    signed = ";".join(sorted(folded))
    canonical_headers = "".join(f"{k}:{folded[k]}\n" for k in sorted(folded))
    canonical = "\n".join(
        [
            request.method.upper(),
            canonical_path,
            canonical_query,
            canonical_headers,
            signed,
            payload_hash,
        ]
    )
    return canonical, signed


def sigv4_signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    """The four-round HMAC chain. Scoped to date, region and service by design."""

    def sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = sign(f"AWS4{secret}".encode(), datestamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    return sign(k_service, "aws4_request")


class SigV4Auth(Authorizer):
    """Signs each request individually, over its own body and timestamp.

    The signature covers the payload hash, so this cannot be a header set once at
    construction — and it covers ``x-amz-date`` to a 15-minute window, so it cannot
    be cached either. Both facts are why the client re-authorises per attempt.
    """

    def __init__(
        self,
        *,
        access_key_id: Credential,
        secret_access_key: Credential,
        region: Credential | str,
        service: str = "cloudtrail",
        session_token: Credential | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.service = service
        self.session_token = session_token
        self.clock = clock
        self.signed = 0
        self.describes = f"AWS SigV4 ({service})"

    def region_name(self) -> str:
        if isinstance(self.region, str):
            return self.region
        require(self.region)
        return self.region.value

    async def apply(self, request: Request) -> Request:
        require(self.access_key_id, self.secret_access_key)
        region = self.region_name()
        now = self.clock()
        amzdate = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
        datestamp = amzdate[:8]
        body = request.body_bytes()
        payload_hash = hashlib.sha256(body).hexdigest()
        headers: dict[str, str] = {
            "host": request.host(),
            "x-amz-date": amzdate,
            "x-amz-content-sha256": payload_hash,
        }
        # Only headers that are actually sent may be signed, and every signed header
        # must be sent. Content-Type is in the set because these APIs are JSON-RPC
        # over POST and AWS signs it; X-Amz-Target likewise, and it is set by the
        # caller, so it is picked up from the request rather than assumed.
        for key, value in request.headers.items():
            low = key.lower()
            if low.startswith("x-amz-") or low in ("content-type",):
                headers[low] = value
        ctype = request.content_type()
        if ctype and "content-type" not in headers:
            headers["content-type"] = ctype
        if self.session_token is not None and self.session_token.configured:
            headers["x-amz-security-token"] = self.session_token.value
        canonical, signed_headers = sigv4_canonical_request(
            request, headers=headers, payload_hash=payload_hash
        )
        scope = f"{datestamp}/{region}/{self.service}/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amzdate,
                scope,
                hashlib.sha256(canonical.encode()).hexdigest(),
            ]
        )
        key = sigv4_signing_key(
            self.secret_access_key.value, datestamp, region, self.service
        )
        signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key_id.value}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        self.signed += 1
        return _with_headers(request, headers)

    def stats(self) -> dict[str, Any]:
        return {"sigv4_signed": self.signed}


__all__ = [
    "ASSUMED_TOKEN_LIFETIME",
    "Authorizer",
    "CredentialsIncomplete",
    "JWT_LIFETIME_SECONDS",
    "OAuth2ClientCredentials",
    "REFRESH_MARGIN_SECONDS",
    "ServiceAccount",
    "ServiceAccountJwtAuth",
    "SigV4Auth",
    "StaticHeaderAuth",
    "Token",
    "require",
    "sigv4_canonical_request",
    "sigv4_signing_key",
]
