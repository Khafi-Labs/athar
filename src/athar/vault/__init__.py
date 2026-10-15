"""Vault subsystem for Athar verifiable erasure receipts."""

from athar.vault.blind_index import compute_blind_index, generate_blind_index_key
from athar.vault.filestore import FileStore, FileStoreError
from athar.vault.schema import (
    EncryptedRecord,
    KeyRecord,
    KeyStore,
    RecordStore,
    SubjectRecord,
    SubjectStore,
    create_tables,
)
from athar.vault.vault import DecryptionError, RecordNotFoundError, Vault, VaultError

__all__ = [
    "DecryptionError",
    "EncryptedRecord",
    "FileStore",
    "FileStoreError",
    "KeyRecord",
    "KeyStore",
    "RecordNotFoundError",
    "RecordStore",
    "SubjectRecord",
    "SubjectStore",
    "Vault",
    "VaultError",
    "compute_blind_index",
    "create_tables",
    "generate_blind_index_key",
]
