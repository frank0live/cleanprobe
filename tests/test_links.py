"""Unit tests for VLESS link parsing and validation."""

from __future__ import annotations

from cleanprobe.links import parse_file, parse_vless

# A REALITY public key is 32 raw bytes, base64url-encoded (43 chars, no padding).
# This one contains '+' and '/' when expressed in standard base64, so it exercises
# the query-string decoding path that plain parse_qs gets wrong.
PBK_STANDARD_B64 = "o5h8eHel+LkZgnKZbZaHKmVGcd7YJG8op1St8D/zJEs"

VALID_REALITY = (
    "vless://ef06a9c3-b9c3-4778-b366-4294f20e6e8d@example.com:443"
    "?encryption=none&security=reality&sni=www.example.com"
    f"&pbk=o5h8eHel-LkZgnKZbZaHKmVGcd7YJG8op1St8D_zJEs&sid=9784d94596f95b"
    "&fp=chrome&type=tcp&flow=xtls-rprx-vision#Node%20One"
)


def test_parse_valid_reality_link() -> None:
    info = parse_vless(VALID_REALITY)
    assert info.ok, info.errors
    assert info.uuid == "ef06a9c3-b9c3-4778-b366-4294f20e6e8d"
    assert info.host == "example.com"
    assert info.port == 443
    assert info.security == "reality"
    assert info.sni == "www.example.com"
    assert info.name == "Node One"


def test_rejects_non_vless_scheme() -> None:
    info = parse_vless("vmess://abc@example.com:443")
    assert not info.ok
    assert any("scheme" in e for e in info.errors)


def test_rejects_malformed_uuid() -> None:
    info = parse_vless(VALID_REALITY.replace("ef06a9c3", "not-a-uuid"))
    assert not info.ok
    assert "uuid is not a valid UUID" in info.errors


def test_requires_sni_and_pbk_for_reality() -> None:
    info = parse_vless(
        "vless://ef06a9c3-b9c3-4778-b366-4294f20e6e8d@example.com:443"
        "?encryption=none&security=reality"
    )
    assert not info.ok
    assert any("requires sni=" in e for e in info.errors)
    assert any("requires pbk=" in e for e in info.errors)


def test_rejects_pbk_of_wrong_length() -> None:
    info = parse_vless(VALID_REALITY.replace("o5h8eHel-LkZgnKZbZaHKmVGcd7YJG8op1St8D_zJEs", "dG9vc2hvcnQ"))
    assert not info.ok
    assert any("32-byte" in e for e in info.errors)


def test_rejects_non_hex_sid() -> None:
    info = parse_vless(VALID_REALITY.replace("sid=9784d94596f95b", "sid=zzzz"))
    assert not info.ok
    assert any("sid must be hex" in e for e in info.errors)


def test_port_out_of_range() -> None:
    info = parse_vless(VALID_REALITY.replace(":443", ":70000"))
    assert not info.ok
    assert "port out of range" in info.errors


def test_warns_on_unknown_security() -> None:
    info = parse_vless(
        "vless://ef06a9c3-b9c3-4778-b366-4294f20e6e8d@example.com:8443"
        "?encryption=none&security=tls&type=xhttp&path=/cloudapi/&sni=example.com"
    )
    assert info.ok, info.errors
    assert any("not REALITY" in w for w in info.warnings)


def test_reality_pbk_with_plus_survives_query_decoding() -> None:
    """'+' in a query value must not decay into a space.

    Standard base64 uses '+' for index 62; a REALITY pbk that happens to contain
    it is still a valid 32-byte key. parse_qs() decodes '+' as a space, which
    corrupts the key and makes the length check fail on a link that is fine.
    """
    link = (
        "vless://ef06a9c3-b9c3-4778-b366-4294f20e6e8d@example.com:443"
        "?encryption=none&security=reality&sni=www.example.com"
        f"&pbk={PBK_STANDARD_B64}&sid=9784d94596f95b&fp=chrome&type=tcp"
    )
    info = parse_vless(link)
    assert info.ok, info.errors
    assert info.params["pbk"][0] == PBK_STANDARD_B64


def test_parse_file_skips_comments_and_blanks(tmp_path) -> None:
    path = tmp_path / "links.txt"
    path.write_text(
        "# a comment line\n\n" + VALID_REALITY + "\n   \n# another comment\n",
        encoding="utf-8",
    )
    infos = parse_file(str(path))
    assert len(infos) == 1
    assert infos[0].ok
