"""CLI smoke tests: the working commands work, the unfinished ones fail loudly."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from athar.cli import main


def test_no_command_prints_help_and_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


@pytest.mark.parametrize(
    "argv",
    [
        ["enroll"],
        ["erase", "--subject-id", "s1"],
        ["receipt", "--job-id", "j1"],
        ["status", "--job-id", "j1"],
    ],
)
def test_unimplemented_commands_exit_2(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == 2
    assert "not implemented" in capsys.readouterr().err


def _flip_first_string(obj: Any) -> bool:
    """Change one character of the first long string value (not the signature)."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str) and len(value) > 8 and "signature" not in key:
                obj[key] = value[:-1] + ("0" if value[-1] != "0" else "1")
                return True
            if _flip_first_string(value):
                return True
    elif isinstance(obj, list):
        return any(_flip_first_string(item) for item in obj)
    return False


def test_demo_receipt_verifies_and_a_tampered_one_does_not(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    pub = tmp_path / "issuer.pub"
    assert main(["demo", "--receipt-out", str(receipt), "--public-key-out", str(pub)]) == 0
    assert main(["verify", "--receipt", str(receipt), "--public-key", str(pub)]) == 0

    data = json.loads(receipt.read_text())
    assert _flip_first_string(data)
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(data))
    assert main(["verify", "--receipt", str(tampered), "--public-key", str(pub)]) != 0


def test_verify_missing_file_fails(tmp_path: Path) -> None:
    assert main(["verify", "--receipt", str(tmp_path / "nope.json")]) != 0
