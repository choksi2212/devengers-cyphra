"""Indicator extraction from an OCSF event.

Where the entity resolver extracts *identities* from an event, this
module extracts *indicators* — IPs, domains, hashes, URLs — that an
intel feed can match against.

The extractor is narrow on purpose. It walks the event's known shapes
and produces a list of (kind, value) pairs. The enrich layer feeds
each pair to :meth:`IntelStore.lookup` and merges any hits into the
event's intel context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from intel.feed import IndicatorKind


_HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_DOMAIN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL = re.compile(r"^https?://[^\s]+$")


@dataclass
class ExtractedIndicator:
    """An indicator extracted from an event."""

    kind: int
    value: str
    field: str  # the dotted path it came from — for the analyst UI


def _hash_kind(text: str) -> int | None:
    """A 64-char hex is SHA-256, 40 is SHA-1, 32 is MD5. Returns ``None``
    if the length does not match a known hash kind."""
    if _HASH_SHA256.match(text):
        return int(IndicatorKind.HASH_SHA256)
    if _HASH_SHA1.match(text):
        return int(IndicatorKind.HASH_SHA1)
    if _HASH_MD5.match(text):
        return int(IndicatorKind.HASH_MD5)
    return None


def _classify_host_or_domain(value: str) -> int:
    """A bare ``8.8.8.8`` is an IP; ``example.com`` is a domain; the
    ``https://example.com/path`` form is a URL. The three regexes are
    matched in order of specificity."""
    if _IP.match(value):
        return int(IndicatorKind.IP)
    if _URL.match(value):
        return int(IndicatorKind.URL)
    if _DOMAIN.match(value):
        return int(IndicatorKind.DOMAIN)
    return 0


class IndicatorExtractor:
    """Extract (kind, value) pairs from an OCSF event."""

    def extract(self, event: Mapping[str, Any]) -> list[ExtractedIndicator]:
        out: list[ExtractedIndicator] = []
        # Source IP — the most common indicator.
        ip = event.get("src_endpoint_ip")
        if _IP.match(str(ip or "")):
            out.append(ExtractedIndicator(
                kind=int(IndicatorKind.IP),
                value=str(ip),
                field="src_endpoint_ip",
            ))
        # Email — for 4009 events. Email address itself is a useful
        # indicator; the domain part is too.
        email = event.get("email")
        if isinstance(email, Mapping):
            for key in ("from", "to"):
                values = email.get(key)
                if isinstance(values, list):
                    for v in values:
                        self._extract_email(v, key, out)
                else:
                    self._extract_email(values, key, out)
        # DNS query — the queried name is an indicator.
        unmapped = event.get("unmapped") or {}
        if isinstance(unmapped, Mapping):
            dns = unmapped.get("dns_query")
            if isinstance(dns, Mapping):
                name = dns.get("name")
                if isinstance(name, str) and _DOMAIN.match(name.lower()):
                    out.append(ExtractedIndicator(
                        kind=int(IndicatorKind.DOMAIN),
                        value=name.lower(),
                        field="unmapped.dns_query.name",
                    ))
            response = unmapped.get("response")
            if isinstance(response, str) and _IP.match(response):
                out.append(ExtractedIndicator(
                    kind=int(IndicatorKind.IP),
                    value=response,
                    field="unmapped.response",
                ))
        # File hashes — the event may carry them in unmapped.
        if isinstance(unmapped, Mapping):
            hashes = unmapped.get("hashes")
            if isinstance(hashes, Mapping):
                for algo, key in (
                    ("sha256", IndicatorKind.HASH_SHA256),
                    ("sha1", IndicatorKind.HASH_SHA1),
                    ("md5", IndicatorKind.HASH_MD5),
                ):
                    text = hashes.get(algo)
                    if isinstance(text, str) and _hash_kind(text.strip()) == int(key):
                        out.append(ExtractedIndicator(
                            kind=int(key),
                            value=text.strip().lower(),
                            field=f"unmapped.hashes.{algo}",
                        ))
            # Some events nest hashes inside a ``file`` object.
            file_ = unmapped.get("file")
            if isinstance(file_, Mapping):
                nested = file_.get("hashes")
                if isinstance(nested, Mapping):
                    for algo, key in (
                        ("sha256", IndicatorKind.HASH_SHA256),
                        ("sha1", IndicatorKind.HASH_SHA1),
                        ("md5", IndicatorKind.HASH_MD5),
                    ):
                        text = nested.get(algo)
                        if isinstance(text, str):
                            hash_kind = _hash_kind(text.strip())
                            if hash_kind == int(key):
                                out.append(ExtractedIndicator(
                                    kind=int(key),
                                    value=text.strip().lower(),
                                    field=f"unmapped.file.hashes.{algo}",
                                ))
        return out

    def _extract_email(self, value: Any, field: str, out: list) -> None:
        text = str(value or "").strip()
        if not _EMAIL.match(text):
            return
        out.append(ExtractedIndicator(
            kind=int(IndicatorKind.EMAIL),
            value=text.lower(),
            field=f"email.{field}",
        ))
        _, _, domain = text.rpartition("@")
        if _DOMAIN.match(domain.lower()):
            out.append(ExtractedIndicator(
                kind=int(IndicatorKind.DOMAIN),
                value=domain.lower(),
                field=f"email.{field}.domain",
            ))


__all__ = ["ExtractedIndicator", "IndicatorExtractor"]
