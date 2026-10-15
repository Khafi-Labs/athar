"""Abstract base class and types for the Athar keystore subsystem."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum


class KeyTier(str, Enum):
    """Hierarchical key tiers in the Athar cryptographic model."""

    KEK = "KEK"  # Key Encryption Key: top-tier, simulates KMS/HSM root
    PPK = "PPK"  # Purpose-Period Key: wrapped by KEK, scoped to purpose & period
    DEK = "DEK"  # Data Encryption Key: wrapped by PPK, scoped to subject


class KeyStatus(str, Enum):
    """Lifecycle status of a cryptographic key."""

    ACTIVE = "ACTIVE"
    SCHEDULED_DESTRUCTION = "SCHEDULED_DESTRUCTION"
    DESTROYED = "DESTROYED"
    COMPROMISED = "COMPROMISED"


class KeystoreError(Exception):
    """Base exception for all keystore operations."""


class KeyNotFoundError(KeystoreError):
    """Raised when an operation requests a non-existent key."""


class KeyDestroyedError(KeystoreError):
    """Raised when an operation attempts to use or unwrap a destroyed key."""


class KeyCompromisedError(KeystoreError):
    """Raised when an operation attempts to use a compromised key."""


class KeyWrappingError(KeystoreError):
    """Raised when key wrapping or unwrapping fails."""


@dataclass
class KeyMetadata:
    """Metadata describing a key in the keystore."""

    key_id: str
    tier: KeyTier
    status: KeyStatus
    created_at: datetime
    scheduled_destruction: datetime | None = None
    destroyed_at: datetime | None = None
    parent_key_id: str | None = None
    purpose: str | None = None
    period: str | None = None
    subject_pseudonym: str | None = None


class KeystoreInterface(ABC):
    """Abstract interface defining the contract for Athar keystore implementations."""

    @abstractmethod
    def generate_kek(self) -> str:
        """Generate a new top-tier Key Encryption Key (KEK).

        Returns:
            The generated KEK's unique identifier (UUID).
        """
        ...

    @abstractmethod
    def generate_ppk(self, kek_id: str, purpose: str, period: str) -> str:
        """Generate a Purpose-Period Key (PPK) wrapped by the specified KEK.

        Args:
            kek_id: UUID of the parent KEK.
            purpose: Processing purpose (e.g., 'kyc_verification', 'credit_scoring').
            period: Temporal retention period (e.g., '2026-Q1', '2026-03').

        Returns:
            The generated PPK's unique identifier (UUID).
        """
        ...

    @abstractmethod
    def generate_dek(self, ppk_id: str, subject_pseudonym: str) -> str:
        """Generate a Data Encryption Key (DEK) wrapped by the specified PPK.

        Args:
            ppk_id: UUID of the parent PPK.
            subject_pseudonym: Opaque pseudonym identifying the subject.

        Returns:
            The generated DEK's unique identifier (UUID).
        """
        ...

    @abstractmethod
    def wrap_key(self, key_material: bytes, wrapping_key_id: str) -> bytes:
        """Wrap (encrypt) raw key material using AES-256-GCM under the wrapping key.

        Args:
            key_material: Raw secret key bytes to protect.
            wrapping_key_id: UUID of the key used to wrap.

        Returns:
            Authenticated ciphertext bytes containing nonce and ciphertext+tag.
        """
        ...

    @abstractmethod
    def unwrap_key(self, wrapped: bytes, wrapping_key_id: str) -> bytes:
        """Unwrap (decrypt) wrapped key material using the specified wrapping key.

        Args:
            wrapped: Authenticated ciphertext bytes containing nonce and ciphertext+tag.
            wrapping_key_id: UUID of the key used to unwrap.

        Returns:
            The unwrapped raw secret key bytes.
        """
        ...

    @abstractmethod
    def get_key(self, key_id: str) -> bytes:
        """Retrieve unwrapped key material for in-memory operations.

        Transparently unwraps parent keys recursively. If the key or any of
        its ancestor wrapping keys has been destroyed, access fails.

        Args:
            key_id: UUID of the key to retrieve.

        Returns:
            Raw secret key bytes.

        Raises:
            KeyNotFoundError: If the key does not exist.
            KeyDestroyedError: If the key or any ancestor has been destroyed.
        """
        ...

    @abstractmethod
    def schedule_destruction(self, key_id: str, grace_period: timedelta) -> None:
        """Schedule a key for destruction after a grace period.

        Args:
            key_id: UUID of the key to schedule.
            grace_period: Time duration until the key becomes eligible for destruction.
        """
        ...

    @abstractmethod
    def destroy_key(self, key_id: str) -> None:
        """Cryptographically destroy a key (SIMULATED in MVP).

        Overwrites key material in-memory with zeros and marks status as DESTROYED.

        Args:
            key_id: UUID of the key to destroy.
        """
        ...

    @abstractmethod
    def get_metadata(self, key_id: str) -> KeyMetadata:
        """Retrieve metadata for a key.

        Args:
            key_id: UUID of the key.

        Returns:
            KeyMetadata object.
        """
        ...

    @abstractmethod
    def list_children(self, key_id: str) -> list[str]:
        """List all child key IDs directly wrapped by the specified key.

        Args:
            key_id: UUID of the parent key.

        Returns:
            List of child key UUIDs.
        """
        ...

    @abstractmethod
    def destroy_cascade(self, ppk_id: str) -> list[str]:
        """Destroy a PPK and all of its wrapped DEKs.

        Args:
            ppk_id: UUID of the PPK to destroy.

        Returns:
            List of all destroyed key IDs (including the PPK and child DEKs).
        """
        ...
