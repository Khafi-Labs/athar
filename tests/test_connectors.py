"""Unit tests for Athar purge connectors across all storage surfaces."""

import tempfile

from athar.erasure.connectors import (
    CacheConnector,
    DatabaseConnector,
    FileStoreConnector,
    LogConnector,
    SearchIndexConnector,
)


def test_database_connector_lifecycle() -> None:
    conn = DatabaseConnector()
    subject = "sub_db_user_123"

    # Insert test records
    conn.insert_record("rec_1", subject, "kyc_verification", "encrypted_payload_1")
    conn.insert_record("rec_2", subject, "kyc_verification", "encrypted_payload_2")
    conn.insert_record("rec_3", "other_user", "kyc_verification", "encrypted_payload_3")

    remnants = conn.scan_for_remnants(subject)
    assert len(remnants) == 2

    # Purge
    target = conn.purge(subject, "kyc_verification")
    assert target.status == "purged"
    assert target.rows_affected == 2
    assert target.surface_name == "database"

    # Scan confirms zero remnants
    assert conn.scan_for_remnants(subject) == []
    assert len(conn.scan_for_remnants("other_user")) == 1

    # Idempotence: second purge call succeeds with 0 rows affected
    target_repeat = conn.purge(subject, "kyc_verification")
    assert target_repeat.status == "purged"
    assert target_repeat.rows_affected == 0


def test_filestore_connector_lifecycle() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn = FileStoreConnector(storage_dir=tmp_dir)
        subject = "sub_fs_user_456"

        conn.store_file("doc1", subject, b"encrypted-doc-1")
        conn.store_file("doc2", subject, b"encrypted-doc-2")
        conn.store_file("doc3", "other_user", b"encrypted-doc-3")

        remnants = conn.scan_for_remnants(subject)
        assert len(remnants) == 2

        # Purge
        target = conn.purge(subject, "kyc_verification")
        assert target.status == "purged"
        assert target.files_affected == 2

        # Scan confirms zero remnants
        assert conn.scan_for_remnants(subject) == []
        assert len(conn.scan_for_remnants("other_user")) == 1

        # Idempotence
        repeat = conn.purge(subject, "kyc_verification")
        assert repeat.status == "purged"
        assert repeat.files_affected == 0


def test_cache_connector_lifecycle() -> None:
    conn = CacheConnector()
    subject = "sub_cache_user_789"

    conn.set("session:sub_cache_user_789:01", {"auth": True}, subject_pseudonym=subject)
    conn.set("session:sub_cache_user_789:02", {"auth": True}, subject_pseudonym=subject)
    conn.set("session:other:99", {"auth": True}, subject_pseudonym="other_user")

    remnants = conn.scan_for_remnants(subject)
    assert len(remnants) == 2

    target = conn.purge(subject, "any")
    assert target.status == "purged"
    assert target.rows_affected == 2

    assert conn.scan_for_remnants(subject) == []
    assert len(conn.scan_for_remnants("other_user")) == 1

    repeat = conn.purge(subject, "any")
    assert repeat.status == "purged"
    assert repeat.rows_affected == 0


def test_search_index_connector_lifecycle() -> None:
    conn = SearchIndexConnector()
    subject = "sub_search_user_101"

    conn.index_document("doc_01", subject, "user profile doc 1")
    conn.index_document("doc_02", subject, "user profile doc 2")
    conn.index_document("doc_03", "other_user", "other profile")

    remnants = conn.scan_for_remnants(subject)
    assert len(remnants) == 2

    target = conn.purge(subject, "marketing")
    assert target.status == "purged"
    assert target.rows_affected == 2

    assert conn.scan_for_remnants(subject) == []
    assert len(conn.scan_for_remnants("other_user")) == 1

    repeat = conn.purge(subject, "marketing")
    assert repeat.status == "purged"
    assert repeat.rows_affected == 0


def test_log_connector_lifecycle() -> None:
    conn = LogConnector()
    subject = "sub_log_user_202"

    conn.append_log("log_1", f"User login observed for {subject}", subject_pseudonym=subject)
    conn.append_log("log_2", f"Data export requested by {subject}", subject_pseudonym=subject)
    conn.append_log("log_3", "System maintenance event", subject_pseudonym=None)

    remnants = conn.scan_for_remnants(subject)
    assert len(remnants) == 2

    target = conn.purge(subject, "kyc_verification")
    assert target.status == "purged"
    assert target.rows_affected == 2

    # Scans confirm pseudonym redacted
    assert conn.scan_for_remnants(subject) == []

    # Check that content was redacted with Athar placeholder
    for entry in conn._logs:
        assert subject not in entry["message"]
        if entry["entry_id"] in ("log_1", "log_2"):
            assert "[REDACTED_BY_ATHAR]" in entry["message"]

    repeat = conn.purge(subject, "kyc_verification")
    assert repeat.status == "purged"
    assert repeat.rows_affected == 0
