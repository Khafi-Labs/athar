"""Vault: Encrypted record storage using AEAD (AES-256-GCM) with cryptographic erasure.

Every record is encrypted using a subject-specific Data Encryption Key (DEK).
Associated Authenticated Data (AAD) cryptographically binds the ciphertext to:
- subject: The pseudonym of the data subject
- purpose: The authorized processing purpose
- record_id: The unique record identifier

The AAD is serialized using RFC 8785 Canonical JSON to guarantee bit-for-bit
determinism across all systems and verifiers.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from athar.crypto.canonical_json import canonical_json
from athar.keystore.interface import KeyDestroyedError, KeyStatus, KeystoreInterface
from athar.vault.schema import EncryptedRecord, RecordStore, SubjectStore

logger = logging.getLogger("athar.vault")


class VaultError(Exception):
    """Base exception for all vault operations."""


class RecordNotFoundError(VaultError):
    """Raised when a requested record ID is not found."""


class DecryptionError(VaultError):
    """Raised when decryption fails due to corrupted ciphertext or tag mismatch."""


class Vault:
    """Encrypted record vault implementing cryptographic erasure through the Athar Keystore."""

    def __init__(
        self,
        keystore: KeystoreInterface,
        default_ppk_id: str | None = None,
        record_store: RecordStore | None = None,
        subject_store: SubjectStore | None = None,
    ) -> None:
        """Initialize the encrypted vault.

        Args:
            keystore: Concrete implementation of KeystoreInterface.
            default_ppk_id: Optional PPK UUID to wrap newly created DEKs under.
            record_store: Optional SQLite RecordStore DAO for persistence.
            subject_store: Optional SQLite SubjectStore DAO for persistence.
        """
        self.keystore = keystore
        self._ppk_id = default_ppk_id
        self._record_store = record_store
        self._subject_store = subject_store

        # In-memory record storage: record_id -> EncryptedRecord
        self._records: dict[str, EncryptedRecord] = {}

        # In-memory subject DEK cache: subject_pseudonym -> dek_id
        self._subject_deks: dict[str, str] = {}

    @property
    def ppk_id(self) -> str | None:
        """Return the current active PPK ID."""
        return self._ppk_id

    def set_active_ppk(self, ppk_id: str) -> None:
        """Set the active PPK ID for subsequent DEK generation."""
        self._ppk_id = ppk_id

    def _ensure_active_ppk(self, purpose: str) -> str:
        """Ensure an active PPK is available for the given purpose, creating a KEK/PPK pair if none exists."""
        if not hasattr(self, "_ppks"):
            self._ppks: dict[str, str] = {}

        if purpose in self._ppks:
            ppk_id = self._ppks[purpose]
            try:
                meta = self.keystore.get_metadata(ppk_id)
                if meta.status == KeyStatus.ACTIVE:
                    return ppk_id
            except Exception:
                pass
        elif self._ppk_id is not None:
            try:
                meta = self.keystore.get_metadata(self._ppk_id)
                if meta.status == KeyStatus.ACTIVE and (
                    meta.purpose == purpose or meta.purpose is None
                ):
                    self._ppks[purpose] = self._ppk_id
                    return self._ppk_id
            except Exception:
                pass

        # Generate new KEK and PPK for the vault
        kek_id = self.keystore.generate_kek()
        period_str = datetime.now(UTC).strftime("%Y-%m")
        ppk_id = self.keystore.generate_ppk(
            kek_id=kek_id,
            purpose=purpose,
            period=period_str,
        )
        self._ppks[purpose] = ppk_id
        self._ppk_id = ppk_id
        logger.info(
            "Auto-provisioned root KEK (%s) and active PPK (%s) for purpose '%s'",
            kek_id,
            ppk_id,
            purpose,
        )
        return ppk_id

    def _get_or_create_dek(self, subject_pseudonym: str, purpose: str) -> str:
        """Retrieve an active DEK for a subject and purpose or generate a new one."""
        cache_key = f"{subject_pseudonym}:{purpose}"
        # Check in-memory cache
        dek_id = self._subject_deks.get(cache_key)

        # Check backing database if available
        if dek_id is None and self._subject_store is not None:
            subj = self._subject_store.get(subject_pseudonym)
            if subj and subj.dek_id and (subj.purpose_id == purpose or subj.purpose_id is None):
                dek_id = subj.dek_id

        # Verify key is still valid and active in keystore
        if dek_id is not None:
            try:
                meta = self.keystore.get_metadata(dek_id)
                if meta.status == KeyStatus.ACTIVE:
                    self._subject_deks[cache_key] = dek_id
                    return dek_id
            except Exception:
                pass

        # Generate new DEK under the active PPK
        active_ppk = self._ensure_active_ppk(purpose)
        dek_id = self.keystore.generate_dek(
            ppk_id=active_ppk,
            subject_pseudonym=subject_pseudonym,
        )
        self._subject_deks[cache_key] = dek_id

        if self._subject_store is not None:
            self._subject_store.upsert(
                pseudonym=subject_pseudonym,
                purpose_id=purpose,
                dek_id=dek_id,
            )

        return dek_id

    def store_record(self, subject_pseudonym: str, purpose: str, plaintext: bytes) -> str:
        """Encrypt and store a record under the subject's DEK with AEAD bindings.

        Args:
            subject_pseudonym: Opaque pseudonym identifying the data subject.
            purpose: Processing purpose.
            plaintext: Raw data bytes to protect.

        Returns:
            UUID of the newly created encrypted record.

        Raises:
            TypeError: If plaintext is not bytes.
            VaultError: If encryption fails.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes or bytearray")

        record_id = str(uuid.uuid4())
        dek_id = self._get_or_create_dek(subject_pseudonym, purpose)

        # Build RFC 8785 canonical JSON AAD binding subject, purpose, and record_id
        aad_data = {
            "purpose": purpose,
            "record_id": record_id,
            "subject": subject_pseudonym,
        }
        aad = canonical_json(aad_data)

        # Retrieve raw DEK and encrypt with AES-256-GCM
        dek_bytes = self.keystore.get_key(dek_id)
        nonce = os.urandom(12)  # 96-bit nonce
        aesgcm = AESGCM(dek_bytes)
        ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), aad)

        record = EncryptedRecord(
            record_id=record_id,
            subject_pseudonym=subject_pseudonym,
            purpose=purpose,
            ciphertext=ciphertext,
            nonce=nonce,
            aad=aad,
            dek_id=dek_id,
            created_at=datetime.now(UTC),
        )

        self._records[record_id] = record

        if self._record_store is not None:
            self._record_store.insert(record)

        logger.debug(
            "Stored record %s for subject %s under DEK %s (purpose=%s)",
            record_id,
            subject_pseudonym,
            dek_id,
            purpose,
        )
        return record_id

    def retrieve_record(self, record_id: str) -> bytes:
        """Decrypt and retrieve a record by its record ID.

        Args:
            record_id: UUID of the record to retrieve.

        Returns:
            Original plaintext bytes.

        Raises:
            RecordNotFoundError: If record_id does not exist.
            KeyDestroyedError: If DEK or any parent key has been destroyed.
            DecryptionError: If ciphertext integrity check fails.
        """
        # Lookup in memory or backing store
        record = self._records.get(record_id)
        if record is None and self._record_store is not None:
            record = self._record_store.get(record_id)
            if record is not None:
                self._records[record_id] = record

        if record is None:
            raise RecordNotFoundError(f"Record {record_id} not found in vault")

        # Retrieve DEK key material (raises KeyDestroyedError if key or parent is destroyed)
        dek_bytes = self.keystore.get_key(record.dek_id)

        # Decrypt using AES-256-GCM with associated data
        try:
            aesgcm = AESGCM(dek_bytes)
            plaintext = aesgcm.decrypt(record.nonce, record.ciphertext, record.aad)
            return plaintext
        except Exception as exc:
            raise DecryptionError(
                f"Decryption failed for record {record_id}: authentication tag mismatch or corrupted ciphertext"
            ) from exc

    def retrieve(self, subject_pseudonym: str, purpose: str) -> bytes | None:
        """Attempt to retrieve the first record for a subject and purpose.

        Args:
            subject_pseudonym: Pseudonym of the data subject.
            purpose: Processing purpose.

        Returns:
            Plaintext bytes if recoverable, None if no matching records exist.

        Raises:
            KeyDestroyedError: If the record's encryption key has been destroyed.
        """
        for rid in self.list_records(subject_pseudonym):
            rec = self._records.get(rid)
            if rec and rec.purpose == purpose:
                return self.retrieve_record(rid)
        return None

    def list_records(self, subject_pseudonym: str) -> list[str]:
        """List all record IDs belonging to a subject.

        Args:
            subject_pseudonym: Pseudonym of the data subject.

        Returns:
            List of record IDs.
        """
        record_ids: set[str] = set()

        # From in-memory cache
        for rid, rec in self._records.items():
            if rec.subject_pseudonym == subject_pseudonym:
                record_ids.add(rid)

        # From backing store if present
        if self._record_store is not None:
            db_records = self._record_store.list_by_subject(subject_pseudonym)
            for rec in db_records:
                record_ids.add(rec.record_id)

        return sorted(record_ids)

    def delete_record(self, record_id: str) -> None:
        """Delete an encrypted record from the vault.

        Args:
            record_id: UUID of the record to delete.

        Raises:
            RecordNotFoundError: If record_id does not exist.
        """
        found = False
        if record_id in self._records:
            del self._records[record_id]
            found = True

        if self._record_store is not None:
            db_deleted = self._record_store.delete(record_id)
            found = found or db_deleted

        if not found:
            raise RecordNotFoundError(f"Cannot delete non-existent record {record_id}")

        logger.debug("Deleted record %s", record_id)

    def is_recoverable(self, record_id: str) -> bool:
        """Check whether a record can still be cryptographically recovered and decrypted.

        Returns True if the record exists, its DEK and all wrapping parent keys
        are intact and active, and the AEAD authentication tag verifies.
        Returns False if the key was destroyed (cryptographic erasure), deleted,
        or corrupted.

        Args:
            record_id: UUID of the record to check.

        Returns:
            True if recoverable, False otherwise.
        """
        try:
            self.retrieve_record(record_id)
            return True
        except (RecordNotFoundError, KeyDestroyedError, DecryptionError, Exception):
            return False
