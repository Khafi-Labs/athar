"""SoftwareKeystore: In-memory reference implementation of the Athar three-tier key hierarchy.

Hierarchy:
  KEK (Key Encryption Key) — top tier, simulates KMS/HSM root
    └── PPK (Purpose-Period Key) — wrapped by KEK
         └── DEK (Data Encryption Key) — wrapped by PPK, per-subject

All non-root key material at rest is encrypted (wrapped by its parent key).
Key destruction is labelled SIMULATED and performs in-place memory overwriting.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from athar.keystore.interface import (
    KeyCompromisedError,
    KeyDestroyedError,
    KeyMetadata,
    KeyNotFoundError,
    KeyStatus,
    KeystoreError,
    KeystoreInterface,
    KeyTier,
    KeyWrappingError,
)

logger = logging.getLogger("athar.keystore")


class SoftwareKeystore(KeystoreInterface):
    """In-memory three-tier keystore implementation.

    Maintains KEK, PPK, and DEK keys with cryptographic wrapping at rest.
    Supports single-key destruction and cascading purpose/period destruction.
    """

    def __init__(self) -> None:
        """Initialize an empty software keystore."""
        # Key storage mapping key_id -> (KeyMetadata, bytearray of raw or wrapped key material)
        self._keys: dict[str, tuple[KeyMetadata, bytearray]] = {}

    def generate_kek(self) -> str:
        """Generate a new top-tier Key Encryption Key (KEK).

        Simulates KMS/HSM root key generation.

        Returns:
            UUID of the newly created KEK.
        """
        key_id = str(uuid.uuid4())
        raw_key = os.urandom(32)  # AES-256
        metadata = KeyMetadata(
            key_id=key_id,
            tier=KeyTier.KEK,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(UTC),
            parent_key_id=None,
            purpose=None,
            period=None,
            subject_pseudonym=None,
        )
        self._keys[key_id] = (metadata, bytearray(raw_key))
        logger.debug("Generated KEK: %s", key_id)
        return key_id

    def generate_ppk(self, kek_id: str, purpose: str, period: str) -> str:
        """Generate a Purpose-Period Key (PPK) wrapped by a KEK.

        Args:
            kek_id: UUID of the parent KEK.
            purpose: Functional purpose for this key (e.g. 'loan_origination').
            period: Time-bounded retention period (e.g. '2026-Q1').

        Returns:
            UUID of the newly created PPK.

        Raises:
            KeyNotFoundError: If kek_id does not exist.
            KeystoreError: If kek_id is not an active KEK.
        """
        kek_meta = self.get_metadata(kek_id)
        if kek_meta.tier != KeyTier.KEK:
            raise KeystoreError(f"Key {kek_id} is tier {kek_meta.tier.value}, expected KEK")
        if kek_meta.status != KeyStatus.ACTIVE:
            raise KeystoreError(
                f"Parent KEK {kek_id} is not active (status: {kek_meta.status.value})"
            )

        key_id = str(uuid.uuid4())
        raw_key = os.urandom(32)
        wrapped_material = self.wrap_key(raw_key, wrapping_key_id=kek_id)

        metadata = KeyMetadata(
            key_id=key_id,
            tier=KeyTier.PPK,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(UTC),
            parent_key_id=kek_id,
            purpose=purpose,
            period=period,
            subject_pseudonym=None,
        )
        self._keys[key_id] = (metadata, bytearray(wrapped_material))
        logger.debug(
            "Generated PPK: %s (purpose=%s, period=%s, parent=%s)", key_id, purpose, period, kek_id
        )
        return key_id

    def generate_dek(self, ppk_id: str, subject_pseudonym: str) -> str:
        """Generate a Data Encryption Key (DEK) wrapped by a PPK for a subject.

        Args:
            ppk_id: UUID of the parent PPK.
            subject_pseudonym: Random pseudonym identifying the subject.

        Returns:
            UUID of the newly created DEK.

        Raises:
            KeyNotFoundError: If ppk_id does not exist.
            KeystoreError: If ppk_id is not an active PPK.
        """
        ppk_meta = self.get_metadata(ppk_id)
        if ppk_meta.tier != KeyTier.PPK:
            raise KeystoreError(f"Key {ppk_id} is tier {ppk_meta.tier.value}, expected PPK")
        if ppk_meta.status != KeyStatus.ACTIVE:
            raise KeystoreError(
                f"Parent PPK {ppk_id} is not active (status: {ppk_meta.status.value})"
            )

        key_id = str(uuid.uuid4())
        raw_key = os.urandom(32)
        wrapped_material = self.wrap_key(raw_key, wrapping_key_id=ppk_id)

        metadata = KeyMetadata(
            key_id=key_id,
            tier=KeyTier.DEK,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(UTC),
            parent_key_id=ppk_id,
            purpose=ppk_meta.purpose,
            period=ppk_meta.period,
            subject_pseudonym=subject_pseudonym,
        )
        self._keys[key_id] = (metadata, bytearray(wrapped_material))
        logger.debug(
            "Generated DEK: %s (subject=%s, parent=%s)",
            key_id,
            subject_pseudonym,
            ppk_id,
        )
        return key_id

    def wrap_key(self, key_material: bytes, wrapping_key_id: str) -> bytes:
        """Wrap key material using AES-256-GCM under the specified wrapping key.

        Payload layout: nonce (12 bytes) || ciphertext + tag (48 bytes) = 60 bytes.

        Args:
            key_material: Raw 32-byte secret key material.
            wrapping_key_id: UUID of the wrapping key.

        Returns:
            Combined nonce and authenticated ciphertext bytes.

        Raises:
            KeyWrappingError: If wrapping fails.
        """
        try:
            wrapping_key = self.get_key(wrapping_key_id)
            nonce = os.urandom(12)
            aad = wrapping_key_id.encode("utf-8")
            aesgcm = AESGCM(wrapping_key)
            ciphertext = aesgcm.encrypt(nonce, key_material, aad)
            return nonce + ciphertext
        except (KeyNotFoundError, KeyDestroyedError, KeyCompromisedError):
            raise
        except Exception as exc:
            raise KeyWrappingError(f"Failed to wrap key under {wrapping_key_id}: {exc}") from exc

    def unwrap_key(self, wrapped: bytes, wrapping_key_id: str) -> bytes:
        """Unwrap wrapped key material using the specified wrapping key.

        Args:
            wrapped: Combined nonce (12 bytes) || ciphertext + tag.
            wrapping_key_id: UUID of the wrapping key.

        Returns:
            Unwrapped raw 32-byte key material.

        Raises:
            KeyWrappingError: If unwrapping fails or payload is malformed.
        """
        if len(wrapped) < 28:  # 12 bytes nonce + 16 bytes auth tag minimum
            raise KeyWrappingError("Wrapped key material is too short")

        try:
            wrapping_key = self.get_key(wrapping_key_id)
            nonce = wrapped[:12]
            ciphertext = wrapped[12:]
            aad = wrapping_key_id.encode("utf-8")
            aesgcm = AESGCM(wrapping_key)
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except (KeyNotFoundError, KeyDestroyedError, KeyCompromisedError):
            raise
        except Exception as exc:
            raise KeyWrappingError(f"Failed to unwrap key using {wrapping_key_id}: {exc}") from exc

    def get_key(self, key_id: str) -> bytes:
        """Retrieve unwrapped raw key material in memory.

        Recursively unwraps parent keys. If this key or any ancestor has been
        destroyed, access is rejected with KeyDestroyedError.

        Args:
            key_id: UUID of the key to unwrap.

        Returns:
            Raw 32-byte secret key material.

        Raises:
            KeyNotFoundError: If key does not exist.
            KeyDestroyedError: If key or any ancestor is destroyed.
            KeyCompromisedError: If key is compromised.
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key {key_id} not found in keystore")

        metadata, stored_material = self._keys[key_id]

        # Check for destroyed status
        if metadata.status == KeyStatus.DESTROYED:
            raise KeyDestroyedError(
                f"[SIMULATED] Key {key_id} ({metadata.tier.value}) has been destroyed"
            )

        if metadata.status == KeyStatus.COMPROMISED:
            raise KeyCompromisedError(f"Key {key_id} is marked COMPROMISED")

        # Check if scheduled destruction has elapsed
        if (
            metadata.status == KeyStatus.SCHEDULED_DESTRUCTION
            and metadata.scheduled_destruction is not None
            and datetime.now(UTC) >= metadata.scheduled_destruction
        ):
            self.destroy_key(key_id)
            raise KeyDestroyedError(
                f"[SIMULATED] Key {key_id} reached scheduled destruction time and was destroyed"
            )

        # KEK is stored as raw bytes (simulating KMS internal secure enclave)
        if metadata.tier == KeyTier.KEK:
            return bytes(stored_material)

        # PPK and DEK are stored wrapped by their parent
        if metadata.parent_key_id is None:
            raise KeystoreError(
                f"Corrupted key record: {metadata.tier.value} {key_id} lacks parent_key_id"
            )

        return self.unwrap_key(bytes(stored_material), wrapping_key_id=metadata.parent_key_id)

    def schedule_destruction(  # type: ignore[override]  # dual signature, see docstring
        self,
        key_id_or_subject: str,
        grace_or_purpose: timedelta | str = timedelta(hours=72),
        scheduled_time: datetime | None = None,
        grace_period: timedelta | None = None,
    ) -> None:
        """Schedule a key or subject's DEKs for destruction after a grace period.

        Supports both:
        - (key_id: str, grace_period: timedelta)
        - (subject_pseudonym: str, purpose: str, scheduled_time: datetime)

        Args:
            key_id_or_subject: Key UUID or subject pseudonym.
            grace_or_purpose: Grace timedelta or purpose string.
            scheduled_time: Optional explicit destruction datetime.
            grace_period: Optional keyword argument for grace duration.
        """
        if grace_period is not None:
            effective_grace: timedelta | str = grace_period
        else:
            effective_grace = grace_or_purpose

        if isinstance(effective_grace, timedelta):
            key_id = key_id_or_subject
            actual_grace = effective_grace
            if key_id not in self._keys:
                raise KeyNotFoundError(f"Key {key_id} not found")

            metadata, _ = self._keys[key_id]
            if metadata.status == KeyStatus.DESTROYED:
                raise KeystoreError(
                    f"Cannot schedule destruction for already destroyed key {key_id}"
                )

            metadata.status = KeyStatus.SCHEDULED_DESTRUCTION
            metadata.scheduled_destruction = datetime.now(UTC) + actual_grace
            logger.info(
                "[SIMULATED] Key %s scheduled for destruction at %s",
                key_id,
                metadata.scheduled_destruction.isoformat(),
            )
        else:
            subject = key_id_or_subject
            purpose = grace_or_purpose
            target_time = scheduled_time or (datetime.now(UTC) + timedelta(hours=72))
            for k_id, (meta, _) in self._keys.items():
                if meta.tier == KeyTier.DEK and meta.subject_pseudonym == subject:
                    if meta.purpose == purpose or purpose == "*":
                        if meta.status != KeyStatus.DESTROYED:
                            meta.status = KeyStatus.SCHEDULED_DESTRUCTION
                            meta.scheduled_destruction = target_time
                            logger.info(
                                "[SIMULATED] Key %s (%s) scheduled for destruction at %s",
                                k_id,
                                meta.tier.value,
                                target_time.isoformat(),
                            )

    def destroy_key(self, key_id: str) -> None:
        """Cryptographically destroy a key (SIMULATED in MVP).

        Overwrites in-memory key material with zeros and marks status as DESTROYED.

        Args:
            key_id: UUID of the key to destroy.

        Raises:
            KeyNotFoundError: If key_id does not exist.
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key {key_id} not found")

        metadata, stored_material = self._keys[key_id]

        if metadata.status == KeyStatus.DESTROYED:
            logger.info("[SIMULATED] Key %s is already destroyed", key_id)
            return

        # In-memory best-effort overwrite with zeros
        for i in range(len(stored_material)):
            stored_material[i] = 0

        metadata.status = KeyStatus.DESTROYED
        metadata.destroyed_at = datetime.now(UTC)

        msg = f"[SIMULATED] Key destroyed: {key_id} (tier: {metadata.tier.value})"
        logger.warning(msg)
        print(msg)

    def get_metadata(self, key_id: str) -> KeyMetadata:
        """Retrieve metadata for a key.

        Args:
            key_id: UUID of the key.

        Returns:
            KeyMetadata object copy.

        Raises:
            KeyNotFoundError: If key_id does not exist.
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key {key_id} not found")

        meta, _ = self._keys[key_id]
        # Return a copy to prevent accidental outside mutation
        return KeyMetadata(
            key_id=meta.key_id,
            tier=meta.tier,
            status=meta.status,
            created_at=meta.created_at,
            scheduled_destruction=meta.scheduled_destruction,
            destroyed_at=meta.destroyed_at,
            parent_key_id=meta.parent_key_id,
            purpose=meta.purpose,
            period=meta.period,
            subject_pseudonym=meta.subject_pseudonym,
        )

    def list_children(self, key_id: str) -> list[str]:
        """List all child key IDs directly wrapped by the specified key.

        Args:
            key_id: UUID of the parent key.

        Returns:
            List of child key UUIDs.

        Raises:
            KeyNotFoundError: If key_id does not exist.
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key {key_id} not found")

        return [k_id for k_id, (meta, _) in self._keys.items() if meta.parent_key_id == key_id]

    def destroy_cascade(self, ppk_id: str) -> list[str]:
        """Destroy a PPK and all of its wrapped DEKs.

        Ensures cryptographic erasure of all records under the purpose/period.

        Args:
            ppk_id: UUID of the PPK to destroy.

        Returns:
            List of all destroyed key IDs (children first, then PPK).

        Raises:
            KeyNotFoundError: If ppk_id does not exist.
            KeystoreError: If ppk_id is not a PPK.
        """
        ppk_meta = self.get_metadata(ppk_id)
        if ppk_meta.tier != KeyTier.PPK:
            raise KeystoreError(f"Key {ppk_id} is tier {ppk_meta.tier.value}, expected PPK")

        destroyed_keys: list[str] = []

        # Find and destroy all child DEKs
        children = self.list_children(ppk_id)
        for child_id in children:
            self.destroy_key(child_id)
            destroyed_keys.append(child_id)

        # Destroy the parent PPK
        self.destroy_key(ppk_id)
        destroyed_keys.append(ppk_id)

        logger.info(
            "[SIMULATED] Cascade destruction complete for PPK %s: %d total keys destroyed",
            ppk_id,
            len(destroyed_keys),
        )
        return destroyed_keys

    def destroy_dek(self, subject_pseudonym: str, purpose: str | None = None) -> list[str]:
        """Destroy DEKs belonging to a subject, optionally filtered by purpose.

        Args:
            subject_pseudonym: Pseudonym of the data subject.
            purpose: Optional purpose filter.

        Returns:
            List of destroyed DEK IDs.
        """
        destroyed: list[str] = []
        for key_id, (meta, _) in list(self._keys.items()):
            if meta.tier == KeyTier.DEK and meta.subject_pseudonym == subject_pseudonym:
                if purpose is None or meta.purpose == purpose:
                    if meta.status != KeyStatus.DESTROYED:
                        self.destroy_key(key_id)
                        destroyed.append(key_id)
        return destroyed

    def has_remaining_purposes(self, subject_pseudonym: str) -> bool:
        """Check whether a subject still has active DEKs for any purpose."""
        for meta, _ in self._keys.values():
            if meta.tier == KeyTier.DEK and meta.subject_pseudonym == subject_pseudonym:
                if meta.status == KeyStatus.ACTIVE:
                    return True
        return False

    def destroy_ppk(self, subject_pseudonym: str) -> list[str]:
        """Hook for PPK destruction once all child DEKs have been destroyed."""
        return []
