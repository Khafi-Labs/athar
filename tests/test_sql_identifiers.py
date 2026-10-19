"""The SQL connector must only accept plain identifiers for table/column names."""

from __future__ import annotations

import pytest

from athar.erasure.connectors import DatabaseConnector


def test_custom_plain_identifiers_work() -> None:
    conn = DatabaseConnector(
        table_name="customer_records",
        subject_column="subject_ref",
        purpose_column="purpose_code",
    )
    conn.insert_record("r1", "pseud-1", "marketing", "x")
    conn.insert_record("r2", "pseud-2", "marketing", "y")
    assert conn.scan_for_remnants("pseud-1") == ["r1"]
    result = conn.purge("pseud-1", "marketing")
    assert result.status == "purged"
    assert result.rows_affected == 1
    assert conn.scan_for_remnants("pseud-1") == []
    assert conn.scan_for_remnants("pseud-2") == ["r2"]


BAD_IDENTIFIERS = [
    "",
    "1starts_with_digit",
    "has space",
    "records; DROP TABLE records",
    "subject_pseudonym OR 1=1",
    "a-b",
    'quote"d',
    "semi;colon",
    "x" * 65,
    "ünïcode",
]


@pytest.mark.parametrize("bad", BAD_IDENTIFIERS)
@pytest.mark.parametrize("field", ["table_name", "subject_column", "purpose_column"])
def test_invalid_identifiers_are_rejected(field: str, bad: str) -> None:
    with pytest.raises(ValueError, match="invalid SQL identifier"):
        DatabaseConnector(**{field: bad})


def test_non_string_identifier_is_rejected() -> None:
    with pytest.raises(ValueError):
        DatabaseConnector(table_name=123)  # type: ignore[arg-type]
