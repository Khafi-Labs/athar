"""Unit tests for Athar Keystore subsystem."""

import time
from datetime import timedelta

import pytest

from athar.keystore import (
    KeyDestroyedError,
    KeyNotFoundError,
    KeyStatus,
    KeystoreError,
    KeyTier,
    KeyWrappingError,
    SoftwareKeystore,
)


def test_generate_three_tier_hierarchy():
    """Verify end-to-end generation of KEK -> PPK -> DEK hierarchy."""
    keystore = SoftwareKeystore()

    # Tier 1: KEK
    kek_id = keystore.generate_kek()
    kek_meta = keystore.get_metadata(kek_id)
    assert kek_meta.tier == KeyTier.KEK
    assert kek_meta.status == KeyStatus.ACTIVE
    assert kek_meta.parent_key_id is None

    # Tier 2: PPK
    ppk_id = keystore.generate_ppk(kek_id, purpose="kyc_verification", period="2026-Q1")
    ppk_meta = keystore.get_metadata(ppk_id)
    assert ppk_meta.tier == KeyTier.PPK
    assert ppk_meta.status == KeyStatus.ACTIVE
    assert ppk_meta.parent_key_id == kek_id
    assert ppk_meta.purpose == "kyc_verification"
    assert ppk_meta.period == "2026-Q1"

    # Tier 3: DEK
    dek_id = keystore.generate_dek(ppk_id, subject_pseudonym="subj-xyz-987")
    dek_meta = keystore.get_metadata(dek_id)
    assert dek_meta.tier == KeyTier.DEK
    assert dek_meta.status == KeyStatus.ACTIVE
    assert dek_meta.parent_key_id == ppk_id
    assert dek_meta.subject_pseudonym == "subj-xyz-987"
    assert dek_meta.purpose == "kyc_verification"

    # Hierarchy navigation
    assert keystore.list_children(kek_id) == [ppk_id]
    assert keystore.list_children(ppk_id) == [dek_id]


def test_key_wrapping_and_unwrapping():
    """Verify AES-256-GCM wrapping and unwrapping correctness."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()

    raw_secret = b"\x42" * 32
    wrapped = keystore.wrap_key(raw_secret, wrapping_key_id=kek_id)

    assert isinstance(wrapped, bytes)
    assert len(wrapped) == 12 + 32 + 16  # nonce + ct + tag
    assert wrapped != raw_secret

    unwrapped = keystore.unwrap_key(wrapped, wrapping_key_id=kek_id)
    assert unwrapped == raw_secret


def test_unwrap_with_invalid_data():
    """Verify wrapping errors on corrupted data."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()

    with pytest.raises(KeyWrappingError):
        keystore.unwrap_key(b"short", wrapping_key_id=kek_id)

    # Tampered ciphertext
    wrapped = keystore.wrap_key(b"\x11" * 32, wrapping_key_id=kek_id)
    tampered = wrapped[:-1] + bytes([wrapped[-1] ^ 0x01])
    with pytest.raises(KeyWrappingError):
        keystore.unwrap_key(tampered, wrapping_key_id=kek_id)


def test_destroy_single_dek():
    """Verify single DEK destruction and memory zero-fill."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()
    ppk_id = keystore.generate_ppk(kek_id, purpose="credit_scoring", period="2026-03")
    dek_id = keystore.generate_dek(ppk_id, subject_pseudonym="subj-111")

    # Key is usable initially
    dek_bytes = keystore.get_key(dek_id)
    assert len(dek_bytes) == 32

    # Destroy the DEK
    keystore.destroy_key(dek_id)

    meta = keystore.get_metadata(dek_id)
    assert meta.status == KeyStatus.DESTROYED
    assert meta.destroyed_at is not None

    # Key retrieval should now fail
    with pytest.raises(KeyDestroyedError):
        keystore.get_key(dek_id)

    # Parent keys remain active
    assert keystore.get_metadata(ppk_id).status == KeyStatus.ACTIVE
    assert keystore.get_metadata(kek_id).status == KeyStatus.ACTIVE


def test_destroy_cascade():
    """Verify cascading destruction of PPK and all child DEKs."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()
    ppk_id = keystore.generate_ppk(kek_id, purpose="audit_log", period="2026-Q1")

    dek1 = keystore.generate_dek(ppk_id, subject_pseudonym="subj-A")
    dek2 = keystore.generate_dek(ppk_id, subject_pseudonym="subj-B")
    dek3 = keystore.generate_dek(ppk_id, subject_pseudonym="subj-C")

    # Verify all DEKs are initially accessible
    assert len(keystore.get_key(dek1)) == 32
    assert len(keystore.get_key(dek2)) == 32
    assert len(keystore.get_key(dek3)) == 32

    # Cascade destroy PPK
    destroyed = keystore.destroy_cascade(ppk_id)
    assert set(destroyed) == {ppk_id, dek1, dek2, dek3}

    # Verify all are marked DESTROYED
    assert keystore.get_metadata(ppk_id).status == KeyStatus.DESTROYED
    assert keystore.get_metadata(dek1).status == KeyStatus.DESTROYED
    assert keystore.get_metadata(dek2).status == KeyStatus.DESTROYED
    assert keystore.get_metadata(dek3).status == KeyStatus.DESTROYED

    # None can be unwrapped
    for d in (dek1, dek2, dek3):
        with pytest.raises(KeyDestroyedError):
            keystore.get_key(d)


def test_parent_destruction_renders_child_unusable():
    """Verify that destroying KEK prevents PPK and DEK from being unwrapped."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()
    ppk_id = keystore.generate_ppk(kek_id, purpose="test", period="2026")
    dek_id = keystore.generate_dek(ppk_id, subject_pseudonym="subj-root-erasure")

    # Verify initial access
    assert len(keystore.get_key(dek_id)) == 32

    # Destroy KEK directly without explicitly destroying DEK
    keystore.destroy_key(kek_id)

    # DEK cannot be unwrapped because its wrapping ancestor is destroyed
    with pytest.raises(KeyDestroyedError):
        keystore.get_key(dek_id)


def test_schedule_destruction():
    """Verify scheduling destruction with grace period."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()
    ppk_id = keystore.generate_ppk(kek_id, purpose="temp", period="now")

    # Schedule destruction 50ms into the future
    keystore.schedule_destruction(ppk_id, grace_period=timedelta(milliseconds=50))
    meta = keystore.get_metadata(ppk_id)
    assert meta.status == KeyStatus.SCHEDULED_DESTRUCTION
    assert meta.scheduled_destruction is not None

    # Wait for grace period to expire
    time.sleep(0.06)

    # Attempting to access key should detect expiration and destroy it
    with pytest.raises(KeyDestroyedError):
        keystore.get_key(ppk_id)

    assert keystore.get_metadata(ppk_id).status == KeyStatus.DESTROYED


def test_invalid_hierarchy_generation():
    """Verify validation when creating keys with invalid parents."""
    keystore = SoftwareKeystore()
    kek_id = keystore.generate_kek()

    # Non-existent parent
    with pytest.raises(KeyNotFoundError):
        keystore.generate_ppk("non-existent-id", purpose="test", period="2026")

    # Attempting to use DEK as parent for PPK
    ppk_id = keystore.generate_ppk(kek_id, purpose="test", period="2026")
    dek_id = keystore.generate_dek(ppk_id, subject_pseudonym="subj-1")

    with pytest.raises(KeystoreError):
        keystore.generate_ppk(dek_id, purpose="invalid", period="2026")
