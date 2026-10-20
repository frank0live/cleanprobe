"""CLI contract tests: the --json flag must work the same way on every subcommand."""

from __future__ import annotations

import json

from cleanprobe.cli import main

LINKS = """\
vless://ef06a9c3-b9c3-4778-b366-4294f20e6e8d@good.example.com:443?encryption=none&security=reality&sni=a.example.com&pbk=o5h8eHel-LkZgnKZbZaHKmVGcd7YJG8op1St8D_zJEs&sid=9784d94596f95b#Good
vless://ef06a9c3-b9c3-4778-b366-4294f20e6e8d@bad.example.com:443?encryption=none&security=reality&sni=b.example.com#NoPbk
"""


def _write(tmp_path, text=LINKS):
    path = tmp_path / "links.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_check_json_reports_every_link(tmp_path) -> None:
    out = tmp_path / "out.json"
    rc = main(["check", _write(tmp_path), "--json", str(out)])

    assert rc == 1, "a file with one invalid link must exit non-zero"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload) == 2
    assert [entry["ok"] for entry in payload] == [True, False]

    good = payload[0]
    assert good["host"] == "good.example.com"
    assert good["security"] == "reality"
    assert good["errors"] == []

    bad = payload[1]
    assert any("pbk" in e for e in bad["errors"])


def test_check_json_all_valid_exits_zero(tmp_path) -> None:
    out = tmp_path / "out.json"
    first_line = LINKS.splitlines()[0]
    rc = main(["check", _write(tmp_path, first_line + "\n"), "--json", str(out)])

    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["ok"] is True
    assert payload[0]["name"] == "Good"


def test_check_without_json_flag_writes_no_file(tmp_path, capsys) -> None:
    main(["check", _write(tmp_path)])
    captured = capsys.readouterr()
    assert "link(s) valid" in captured.out
    assert not list(tmp_path.glob("*.json"))
