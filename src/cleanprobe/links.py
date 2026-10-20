"""VLESS link parsing and validation."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass
class LinkInfo:
    raw: str
    ok: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    uuid: str = ""
    host: str = ""
    port: int = 0
    params: dict = field(default_factory=dict)
    name: str = ""

    @property
    def sni(self) -> str:
        return (self.params.get("sni") or [""])[0]

    @property
    def security(self) -> str:
        return (self.params.get("security") or [""])[0]


def _b64_urlsafe_len(value: str) -> int | None:
    padded = value + "=" * (-len(value) % 4)
    try:
        return len(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _parse_query_keep_plus(query: str) -> dict[str, list[str]]:
    """Split a URI query without the form-encoding '+' -> space rewrite.

    VLESS parameters carry base64 keys (``pbk``); in standard base64 index 62 is
    '+' and is perfectly valid there. ``parse_qs`` applies
    ``application/x-www-form-urlencoded`` rules and turns that '+' into a space,
    which silently corrupts the key. Percent-decoding alone is what a URI query
    actually needs.
    """
    params: dict[str, list[str]] = {}
    for chunk in query.split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        params.setdefault(unquote(key), []).append(unquote(value))
    return params


def parse_vless(uri: str) -> LinkInfo:
    """Parse a vless:// link; collect all problems in `.errors`."""
    info = LinkInfo(raw=uri.strip())
    parsed = urlparse(info.raw)

    if parsed.scheme != "vless":
        info.errors.append(f"unsupported scheme {parsed.scheme!r} (expected vless)")
        return info

    info.uuid = unquote(parsed.username or "")
    if not UUID_RE.match(info.uuid):
        info.errors.append("uuid is not a valid UUID")

    info.host = parsed.hostname or ""
    if not info.host:
        info.errors.append("missing host")
    try:
        info.port = parsed.port or 0
    except ValueError:
        info.port = 0
    if not (1 <= info.port <= 65535):
        info.errors.append("port out of range")

    info.params = _parse_query_keep_plus(parsed.query)
    info.name = unquote(parsed.fragment or "")

    if info.security == "reality":
        if "sni" not in info.params:
            info.errors.append("security=reality requires sni=")
        if "pbk" not in info.params:
            info.errors.append("security=reality requires pbk=")
        else:
            pbk_len = _b64_urlsafe_len(info.params["pbk"][0])
            if pbk_len != 32:
                info.errors.append("pbk does not decode to a 32-byte public key")
        if "sid" in info.params and not re.fullmatch(r"[0-9a-fA-F]{0,16}", info.params["sid"][0]):
            info.errors.append("sid must be hex, at most 16 chars")
        if "flow" in info.params and info.params["flow"][0] not in ("", "xtls-rprx-vision"):
            info.warnings.append(f"unusual flow value {info.params['flow'][0]!r}")
    elif info.security:
        info.warnings.append(f"security={info.security} (not REALITY; parsed anyway)")

    info.ok = not info.errors
    return info


def parse_file(path: str) -> list[LinkInfo]:
    """Parse every non-empty, non-comment line of a links file.

    Note: '#...' inside a line is a link fragment (the display name),
    so only whole lines starting with '#' count as comments.
    """
    out: list[LinkInfo] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if entry and not entry.startswith("#"):
                out.append(parse_vless(entry))
    return out
