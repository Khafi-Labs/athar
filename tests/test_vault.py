"""Unit tests for Athar Vault, Schema, Blind Index, and FileStore subsystems."""

import hashlib
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from athar.keystore import KeyDestroyedError, SoftwareKeystore
from athar.vault import (
    DecryptionError,
    EncryptedRecord,
    FileStore,
    KeyStore,
    RecordNotFoundError,
    RecordStore,
    SubjectStore,
    Vault,
    compute_blind_index,
    create_tables,
    generate_blind_index_key,
)

# ============================================================================
# Vault Core Tests
# ============================================================================


def test_vault_store_and_retrieve_record():
    """Verify normal store and retrieve flow with AES-256-GCM and canonical JSON AAD."""
    keystore = SoftwareKeystore()
    vault = Vault(keystore=keystore)

    subject = "pseudonym-alice-1234"
    purpose = "loan_underwriting"
    plaintext = b"Sensitive financial income data: $120,000"

    record_id = vault.store_record(subject_pseudonym=subject, purpose=purpose, plaintext=plaintext)
    assert record_id is not None

    # Retrieve record
    retrieved = vault.retrieve_record(record_id)
    assert retrieved == plaintext

    # Verify recoverability
    assert vault.is_recoverable(record_id) is True

    # List records
    assert vault.list_records(subject) == [record_id]


def test_vault_cryptographic_erasure_via_dek():
    """Verify cryptographic erasure when a subject's DEK is destroyed."""
    keystore = SoftwareKeystore()
    vault = Vault(keystore=keystore)

    subject = "subj-gdpr-erasure-001"
    purpose = "account_profile"
    plaintext = b"User personal profile payload"

    record_id = vault.store_record(subject_pseudonym=subject, purpose=purpose, plaintext=plaintext)
    assert vault.is_recoverable(record_id) is True

    # Retrieve the DEK used for this subject
    rec = vault._records[record_id]
    dek_id = rec.dek_id

    # Destroy the DEK (simulating crypto-erasure of the subject)
    keystore.destroy_key(dek_id)

    # Verification of cryptographic erasure
    assert vault.is_recoverable(record_id) is False

    with pytest.raises(KeyDestroyedError):
        vault.retrieve_record(record_id)


def test_vault_cascade_erasure_via_ppk():
    """Verify batch cryptographic erasure when a PPK is destroyed."""
    keystore = SoftwareKeystore()
    vault = Vault(keystore=keystore)

    kek_id = keystore.generate_kek()
    ppk_id = keystore.generate_ppk(kek_id, purpose="marketing_campaign", period="2026-Q1")
    vault.set_active_ppk(ppk_id)

    # Store records for multiple subjects under the same PPK
    r1 = vault.store_record("subj-user-1", "marketing_campaign", b"User 1 lead data")
    r2 = vault.store_record("subj-user-2", "marketing_campaign", b"User 2 lead data")

    assert vault.is_recoverable(r1) is True
    assert vault.is_recoverable(r2) is True

    # Destroy the PPK (retention period expiration)
    keystore.destroy_cascade(ppk_id)

    assert vault.is_recoverable(r1) is False
    assert vault.is_recoverable(r2) is False


def test_vault_tamper_detection():
    """Verify that any modification to ciphertext or AAD is rejected by AEAD."""
    keystore = SoftwareKeystore()
    vault = Vault(keystore=keystore)

    record_id = vault.store_record("subj-tamper", "verification", b"Authentic payload")
    record = vault._records[record_id]

    # Tamper with ciphertext
    tampered_ct = record.ciphertext[:-1] + bytes([record.ciphertext[-1] ^ 0x01])
    record.ciphertext = tampered_ct

    with pytest.raises(DecryptionError):
        vault.retrieve_record(record_id)


def test_vault_delete_record():
    """Verify explicit record deletion from vault."""
    keystore = SoftwareKeystore()
    vault = Vault(keystore=keystore)

    rid = vault.store_record("subj-del", "temp", b"To be deleted")
    assert vault.is_recoverable(rid) is True

    vault.delete_record(rid)
    assert vault.is_recoverable(rid) is False

    with pytest.raises(RecordNotFoundError):
        vault.retrieve_record(rid)


# ============================================================================
# Blind Index Tests
# ============================================================================


def test_blind_index_computation():
    """Verify blind index correctness and security properties."""
    hmac_key = generate_blind_index_key()
    assert len(hmac_key) == 32

    email = "user@example.com"
    index1 = compute_blind_index(email, hmac_key)
    index2 = compute_blind_index(email, hmac_key)

    # Determinism for same key
    assert index1 == index2
    assert len(index1) == 64  # SHA-256 hex string

    # Keyed separation: different HMAC key yields completely different index
    other_key = generate_blind_index_key()
    index_other = compute_blind_index(email, other_key)
    assert index1 != index_other

    # Blind index MUST NEVER match plain unkeyed SHA-256 of the personal data
    plain_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
    assert index1 != plain_hash


def test_blind_index_validation():
    """Verify error checking for invalid keys and inputs."""
    valid_key = b"\x01" * 32

    with pytest.raises(TypeError):
        compute_blind_index(12345, valid_key)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        compute_blind_index("test@example.com", "not_bytes")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        compute_blind_index("", valid_key)

    with pytest.raises(ValueError):
        compute_blind_index("test@example.com", b"too-short")


# ============================================================================
# FileStore Tests
# ============================================================================


def test_filestore_lifecycle_and_canary_scan():
    """Verify encrypted file storage, retrieval, canary check, and zero-overwrite deletion."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        store = FileStore(base_dir=tmp_dir)
        keystore = SoftwareKeystore()

        kek_id = keystore.generate_kek()
        ppk_id = keystore.generate_ppk(kek_id, purpose="id_document", period="2026")
        dek_id = keystore.generate_dek(ppk_id, subject_pseudonym="subj-file-user")

        file_content = b"PDF document payload: Passport scan bytes for John Doe"
        file_id = store.store_file(
            subject_pseudonym="subj-file-user",
            purpose="id_document",
            data=file_content,
            dek_id=dek_id,
            keystore=keystore,
        )

        # Retrieval
        recovered = store.retrieve_file(file_id, keystore)
        assert recovered == file_content

        # List files
        assert store.list_files("subj-file-user") == [file_id]

        # Canary check: encrypted files on disk must NOT contain plaintext strings
        leaks = store.scan_for_plaintext("Passport scan bytes")
        assert leaks == []

        # Plant an unencrypted leak file to test canary alert detection
        leak_file = Path(tmp_dir) / "leaked_canary.bin"
        leak_file.write_bytes(b"Unencrypted leak with Passport scan bytes")
        detected_leaks = store.scan_for_plaintext("Passport scan bytes")
        assert "leaked_canary" in detected_leaks
        leak_file.unlink()

        # Delete file with zero-fill overwrite
        store.delete_file(file_id)
        assert not (Path(tmp_dir) / f"{file_id}.enc").exists()
        assert not (Path(tmp_dir) / f"{file_id}.meta").exists()


def test_filestore_crypto_erasure():
    """Verify that destroying DEK prevents file decryption."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        store = FileStore(base_dir=tmp_dir)
        keystore = SoftwareKeystore()

        kek_id = keystore.generate_kek()
        ppk_id = keystore.generate_ppk(kek_id, purpose="contract", period="2026")
        dek_id = keystore.generate_dek(ppk_id, subject_pseudonym="subj-contract-user")

        file_id = store.store_file(
            subject_pseudonym="subj-contract-user",
            purpose="contract",
            data=b"Legal contract content",
            dek_id=dek_id,
            keystore=keystore,
        )

        # Destroy DEK
        keystore.destroy_key(dek_id)

        with pytest.raises(KeyDestroyedError):
            store.retrieve_file(file_id, keystore)


# ============================================================================
# SQLite Schema and DAOs Tests
# ============================================================================


def test_sqlite_schema_and_daos():
    """Verify SQLite table creation and SubjectStore, RecordStore, KeyStore DAOs."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)

    # 1. SubjectStore
    subject_store = SubjectStore(conn)
    hmac_key = generate_blind_index_key()
    b_idx = compute_blind_index("user@athar.dev", hmac_key)

    subj = subject_store.insert(
        pseudonym="subj-sql-001",
        blind_index=b_idx,
        purpose_id="banking",
        dek_id="dek-uuid-1",
    )
    assert subj.pseudonym == "subj-sql-001"

    found_subj = subject_store.get_by_blind_index(b_idx)
    assert found_subj is not None
    assert found_subj.pseudonym == "subj-sql-001"

    # 2. KeyStore DAO
    key_store = KeyStore(conn)
    key_store.insert(
        key_id="kek-sql-1",
        tier="KEK",
        status="ACTIVE",
        wrapped_material=b"\xaa" * 32,
    )
    key_store.insert(
        key_id="dek-uuid-1",
        tier="DEK",
        status="ACTIVE",
        wrapped_material=b"\xbb" * 60,
        parent_key_id="kek-sql-1",
    )
    children = key_store.list_children("kek-sql-1")
    assert len(children) == 1
    assert children[0].id == "dek-uuid-1"

    # 3. RecordStore DAO
    record_store = RecordStore(conn)
    enc_record = EncryptedRecord(
        record_id="rec-001",
        subject_pseudonym="subj-sql-001",
        purpose="banking",
        ciphertext=b"ciphertext_bytes",
        nonce=b"nonce_12byte",
        aad=b"aad_bytes",
        dek_id="dek-uuid-1",
        created_at=datetime.now(UTC),
    )
    record_store.insert(enc_record)

    fetched_rec = record_store.get("rec-001")
    assert fetched_rec is not None
    assert fetched_rec.ciphertext == b"ciphertext_bytes"
    assert fetched_rec.subject_pseudonym == "subj-sql-001"

    by_subj = record_store.list_by_subject("subj-sql-001")
    assert len(by_subj) == 1
    assert by_subj[0].record_id == "rec-001"

    # Delete record
    assert record_store.delete("rec-001") is True
    assert record_store.get("rec-001") is None

    conn.close()


def test_vault_with_sqlite_stores():
    """Verify Vault integration with SQLite SubjectStore and RecordStore."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)

    subject_store = SubjectStore(conn)
    record_store = RecordStore(conn)
    keystore = SoftwareKeystore()

    vault = Vault(
        keystore=keystore,
        record_store=record_store,
        subject_store=subject_store,
    )

    subject = "subj-persistent-user"
    payload = b"Persisted sensitive data through SQLite DAOs"

    rid = vault.store_record(subject_pseudonym=subject, purpose="credit_check", plaintext=payload)

    # Verify persisted in SQLite
    db_rec = record_store.get(rid)
    assert db_rec is not None
    assert db_rec.subject_pseudonym == subject

    # Retrieve through vault
    decrypted = vault.retrieve_record(rid)
    assert decrypted == payload

    conn.close()
