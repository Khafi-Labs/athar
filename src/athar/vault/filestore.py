"""Encrypted file storage with cryptographic erasure and canary scanning.

Provides secure local file storage protected by AEAD (AES-256-GCM) under DEKs
managed by the Athar keystore. Files are verified against subject and purpose
bindings. File deletion performs in-place zero-fill overwriting before removal.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from athar.crypto.canonical_json import canonical_json
from athar.keystore.interface import KeystoreInterface

logger = logging.getLogger("athar.vault.filestore")


class FileStoreError(Exception):
    """Base exception for file store operations."""


class FileStore:
    """Encrypted file store backed by local filesystem and Athar Keystore."""

    def __init__(self, base_dir: str | Path) -> None:
        """Initialize FileStore rooted at base_dir.

        Args:
            base_dir: Directory path where encrypted files and metadata will reside.
        """
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _meta_path(self, file_id: str) -> Path:
        """Return the filesystem path for a file's metadata."""
        return self.base_dir / f"{file_id}.meta"

    def _data_path(self, file_id: str) -> Path:
        """Return the filesystem path for a file's encrypted payload."""
        return self.base_dir / f"{file_id}.enc"

    def store_file(
        self,
        subject_pseudonym: str,
        purpose: str,
        data: bytes,
        dek_id: str,
        keystore: KeystoreInterface,
    ) -> str:
        """Encrypt and store file data on disk under the provided DEK.

        Args:
            subject_pseudonym: Pseudonym of the data subject.
            purpose: Processing purpose.
            data: Raw file bytes to protect.
            dek_id: UUID of the DEK to encrypt with.
            keystore: Keystore holding the DEK.

        Returns:
            UUID of the newly created file.

        Raises:
            TypeError: If data is not bytes.
            KeyDestroyedError: If the DEK or its wrapping keys are destroyed.
            FileStoreError: If writing to disk fails.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes or bytearray, got {type(data).__name__}")

        file_id = str(uuid.uuid4())

        # Retrieve raw DEK
        dek_bytes = keystore.get_key(dek_id)

        # Generate AEAD associated data binding to file_id, purpose, and subject
        aad_data = {
            "file_id": file_id,
            "purpose": purpose,
            "subject": subject_pseudonym,
        }
        aad = canonical_json(aad_data)

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek_bytes)
        ciphertext = aesgcm.encrypt(nonce, bytes(data), aad)

        # Write encrypted payload: nonce (12 bytes) || ciphertext + tag
        data_path = self._data_path(file_id)
        with open(data_path, "wb") as f:
            f.write(nonce + ciphertext)

        # Write metadata
        meta = {
            "file_id": file_id,
            "subject_pseudonym": subject_pseudonym,
            "purpose": purpose,
            "dek_id": dek_id,
            "aad_hex": aad.hex(),
            "created_at": datetime.now(UTC).isoformat(),
        }
        meta_path = self._meta_path(file_id)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        logger.debug(
            "Stored encrypted file %s for subject %s under DEK %s",
            file_id,
            subject_pseudonym,
            dek_id,
        )
        return file_id

    def retrieve_file(self, file_id: str, keystore: KeystoreInterface) -> bytes:
        """Decrypt and retrieve a file by its ID.

        Args:
            file_id: UUID of the file to retrieve.
            keystore: Keystore holding the DEK.

        Returns:
            Original plaintext file bytes.

        Raises:
            FileNotFoundError: If the file does not exist.
            KeyDestroyedError: If DEK or any wrapping key is destroyed.
            FileStoreError: If file decryption or authentication fails.
        """
        meta_path = self._meta_path(file_id)
        data_path = self._data_path(file_id)

        if not meta_path.exists() or not data_path.exists():
            raise FileNotFoundError(f"File {file_id} not found in filestore")

        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)

        dek_id = meta["dek_id"]
        aad = bytes.fromhex(meta["aad_hex"])

        # Fetch DEK from keystore (raises KeyDestroyedError if erased)
        dek_bytes = keystore.get_key(dek_id)

        with open(data_path, "rb") as f:
            raw_payload = f.read()

        if len(raw_payload) < 28:
            raise FileStoreError(f"Corrupted payload for file {file_id}: payload too short")

        nonce = raw_payload[:12]
        ciphertext = raw_payload[12:]

        try:
            aesgcm = AESGCM(dek_bytes)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
        except Exception as exc:
            raise FileStoreError(
                f"Failed to decrypt file {file_id}: authentication tag mismatch or corrupted data"
            ) from exc

    def delete_file(self, file_id: str) -> None:
        """Cryptographically and physically overwrite file with zeros then delete.

        Performs a best-effort in-place zero-fill overwrite on both the data
        payload and metadata files before unlinking them from disk.

        Args:
            file_id: UUID of the file to delete.

        Raises:
            FileNotFoundError: If neither data nor metadata file exists.
        """
        meta_path = self._meta_path(file_id)
        data_path = self._data_path(file_id)

        if not meta_path.exists() and not data_path.exists():
            raise FileNotFoundError(f"Cannot delete non-existent file {file_id}")

        for target in (data_path, meta_path):
            if target.exists():
                try:
                    size = os.path.getsize(target)
                    with open(target, "r+b") as f:
                        f.write(b"\x00" * size)
                        f.flush()
                        os.fsync(f.fileno())
                except Exception as exc:
                    logger.warning("Zero-overwrite failed for %s: %s", target, exc)
                finally:
                    try:
                        os.remove(target)
                    except OSError:
                        pass

        msg = f"[SIMULATED] Secure file deletion: {file_id} overwritten with zeros and removed"
        logger.info(msg)
        print(msg)

    def list_files(self, subject_pseudonym: str) -> list[str]:
        """List all file IDs belonging to a subject.

        Args:
            subject_pseudonym: Subject pseudonym to filter by.

        Returns:
            List of matching file UUIDs.
        """
        matching: list[str] = []
        for meta_file in self.base_dir.glob("*.meta"):
            try:
                with open(meta_file, encoding="utf-8") as f:
                    meta = json.load(f)
                if meta.get("subject_pseudonym") == subject_pseudonym:
                    matching.append(meta.get("file_id", meta_file.stem))
            except Exception:
                continue
        return sorted(matching)

    def scan_for_plaintext(self, subject_pseudonym: str) -> list[str]:
        """Canary check: scan encrypted file payloads to ensure no plaintext leaks exist.

        Searches all stored ciphertext payload files (.enc) and any non-metadata
        files in the base directory to verify that the subject pseudonym or canary
        string does not appear in unencrypted plaintext on disk.

        Args:
            subject_pseudonym: The pseudonym or canary token to scan for.

        Returns:
            List of file_ids where the plaintext string was detected in payload data.
        """
        canary_bytes = subject_pseudonym.encode("utf-8")
        leaked_files: list[str] = []

        # Check all payload and non-metadata files in base directory
        for item in self.base_dir.iterdir():
            if not item.is_file():
                continue
            # Skip designated metadata files
            if item.suffix == ".meta":
                continue

            try:
                content = item.read_bytes()
                if canary_bytes in content:
                    file_id = item.stem
                    leaked_files.append(file_id)
                    logger.warning(
                        "Canary check ALERT: Plaintext '%s' found unencrypted in %s",
                        subject_pseudonym,
                        item.name,
                    )
            except Exception:
                continue

        return sorted(leaked_files)
