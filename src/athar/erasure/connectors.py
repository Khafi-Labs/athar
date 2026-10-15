"""Purge connectors for orchestrating multi-surface data destruction.

Athar coordinates physical erasure across heterogeneous data surfaces (relational databases,
object/file storage, volatile caches, search indexes, and audit logs) prior to cryptographic
key destruction.
"""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class PurgeTarget:
    """State and metrics for a specific storage surface targeted for erasure.

    Attributes:
        surface_name: Unique name of the storage surface (e.g., 'database', 'filestore').
        surface_type: Category of storage (e.g., 'relational_db', 'file_storage').
        status: Current status ('pending', 'purged', 'failed', 'skipped').
        rows_affected: Count of database or index rows deleted/redacted.
        files_affected: Count of physical files deleted.
        error: Error message if the purge failed.
        purged_at: Timestamp when surface purge completed successfully.
    """

    surface_name: str
    surface_type: str
    status: str = "pending"
    rows_affected: int = 0
    files_affected: int = 0
    error: str | None = None
    purged_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert PurgeTarget to JSON-serializable dictionary."""
        return {
            "surface_name": self.surface_name,
            "surface_type": self.surface_type,
            "status": self.status,
            "rows_affected": self.rows_affected,
            "files_affected": self.files_affected,
            "error": self.error,
            "purged_at": self.purged_at.isoformat() if self.purged_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PurgeTarget:
        """Instantiate PurgeTarget from dictionary."""
        purged_at = datetime.fromisoformat(data["purged_at"]) if data.get("purged_at") else None
        return cls(
            surface_name=data["surface_name"],
            surface_type=data["surface_type"],
            status=data.get("status", "pending"),
            rows_affected=data.get("rows_affected", 0),
            files_affected=data.get("files_affected", 0),
            error=data.get("error"),
            purged_at=purged_at,
        )


class PurgeConnector(ABC):
    """Abstract base class for storage surface purge connectors.

    Every connector must implement idempotent deletion and a remnant canary scan.
    """

    surface_name: str
    surface_type: str
    is_idempotent: bool = True

    @abstractmethod
    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        """Purge all records matching the subject pseudonym and purpose.

        This method MUST be idempotent. Repeated invocations must not fail and
        should report 0 newly affected records if already purged.

        Args:
            subject_pseudonym: Opaque subject pseudonym.
            purpose: Processing purpose being erased.

        Returns:
            PurgeTarget with final status and count of deleted records.
        """
        raise NotImplementedError

    @abstractmethod
    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        """Perform a canary check scanning for residual data matching the subject.

        Args:
            subject_pseudonym: Opaque subject pseudonym.

        Returns:
            List of remnant identifiers or locations. Empty list indicates clean surface.
        """
        raise NotImplementedError


class DatabaseConnector(PurgeConnector):
    """Connector for purging records from relational databases (SQLite backed)."""

    def __init__(
        self,
        surface_name: str = "database",
        db_path: str | Path | None = None,
        connection: sqlite3.Connection | None = None,
        table_name: str = "records",
        subject_column: str = "subject_pseudonym",
        purpose_column: str = "purpose",
    ) -> None:
        """Initialize SQLite database connector.

        Args:
            surface_name: Label for this database target.
            db_path: Optional file path to SQLite database. If None and connection is None,
                an in-memory database is initialized.
            connection: Optional existing SQLite connection.
            table_name: Database table containing subject records.
            subject_column: Column name storing the subject pseudonym.
            purpose_column: Column name storing processing purpose.
        """
        self.surface_name = surface_name
        self.surface_type = "relational_db"
        self.table_name = table_name
        self.subject_column = subject_column
        self.purpose_column = purpose_column

        if connection is not None:
            self._conn = connection
        elif db_path is not None:
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        else:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)

        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize the target table if it does not exist."""
        with self._conn:
            self._conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    id TEXT PRIMARY KEY,
                    {self.subject_column} TEXT NOT NULL,
                    {self.purpose_column} TEXT,
                    payload TEXT,
                    created_at TEXT
                )
                """
            )

    def insert_record(
        self,
        record_id: str,
        subject_pseudonym: str,
        purpose: str,
        payload: str = "",
    ) -> None:
        """Helper to insert records for testing and verification."""
        with self._conn:
            self._conn.execute(
                f"""
                INSERT OR REPLACE INTO {self.table_name}
                (id, {self.subject_column}, {self.purpose_column}, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    subject_pseudonym,
                    purpose,
                    payload,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        """Purge matching database records."""
        try:
            with self._conn:
                cursor = self._conn.execute(
                    f"""
                    DELETE FROM {self.table_name}
                    WHERE {self.subject_column} = ?
                      AND ({self.purpose_column} = ? OR {self.purpose_column} IS NULL OR ? = '*')
                    """,
                    (subject_pseudonym, purpose, purpose),
                )
                rows_affected = cursor.rowcount

            return PurgeTarget(
                surface_name=self.surface_name,
                surface_type=self.surface_type,
                status="purged",
                rows_affected=rows_affected,
                files_affected=0,
                purged_at=datetime.now(UTC),
            )
        except Exception as ex:
            return PurgeTarget(
                surface_name=self.surface_name,
                surface_type=self.surface_type,
                status="failed",
                rows_affected=0,
                files_affected=0,
                error=str(ex),
            )

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        """Canary scan for remaining records matching the subject pseudonym."""
        cursor = self._conn.execute(
            f"SELECT id FROM {self.table_name} WHERE {self.subject_column} = ?",
            (subject_pseudonym,),
        )
        return [row[0] for row in cursor.fetchall()]


class FileStoreConnector(PurgeConnector):
    """Connector for purging encrypted files and blob attachments."""

    def __init__(
        self,
        surface_name: str = "filestore",
        storage_dir: str | Path | None = None,
    ) -> None:
        """Initialize FileStoreConnector.

        Args:
            surface_name: Label for the file storage target.
            storage_dir: Optional directory path. If None, in-memory virtual storage is used.
        """
        self.surface_name = surface_name
        self.surface_type = "file_storage"
        self.storage_dir = Path(storage_dir) if storage_dir else None
        self._virtual_files: dict[str, tuple[str, bytes]] = {}  # path -> (subject, content)

        if self.storage_dir:
            self.storage_dir.mkdir(parents=True, exist_ok=True)

    def store_file(
        self,
        file_id: str,
        subject_pseudonym: str,
        content: bytes,
    ) -> str:
        """Store an encrypted file tied to a subject pseudonym."""
        filename = f"{subject_pseudonym}_{file_id}.enc"
        if self.storage_dir:
            file_path = self.storage_dir / filename
            file_path.write_bytes(content)
            return str(file_path)
        else:
            self._virtual_files[filename] = (subject_pseudonym, content)
            return filename

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        """Delete files matching the subject pseudonym."""
        files_deleted = 0
        try:
            if self.storage_dir and self.storage_dir.exists():
                for p in list(self.storage_dir.glob(f"{subject_pseudonym}_*")):
                    if p.is_file():
                        p.unlink()
                        files_deleted += 1
            else:
                to_delete = [
                    k for k, (subj, _) in self._virtual_files.items() if subj == subject_pseudonym
                ]
                for k in to_delete:
                    del self._virtual_files[k]
                    files_deleted += 1

            return PurgeTarget(
                surface_name=self.surface_name,
                surface_type=self.surface_type,
                status="purged",
                rows_affected=0,
                files_affected=files_deleted,
                purged_at=datetime.now(UTC),
            )
        except Exception as ex:
            return PurgeTarget(
                surface_name=self.surface_name,
                surface_type=self.surface_type,
                status="failed",
                rows_affected=0,
                files_affected=files_deleted,
                error=str(ex),
            )

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        """Canary scan for remaining files tied to the pseudonym."""
        remnants: list[str] = []
        if self.storage_dir and self.storage_dir.exists():
            for p in self.storage_dir.glob(f"{subject_pseudonym}_*"):
                remnants.append(str(p.name))
        else:
            for k, (subj, _) in self._virtual_files.items():
                if subj == subject_pseudonym:
                    remnants.append(k)
        return remnants


class CacheConnector(PurgeConnector):
    """Connector for evicting subject keys from volatile in-memory caches."""

    def __init__(self, surface_name: str = "cache") -> None:
        """Initialize CacheConnector with in-memory key-value store."""
        self.surface_name = surface_name
        self.surface_type = "key_value_cache"
        self._cache: dict[str, dict[str, Any]] = {}

    def set(
        self,
        cache_key: str,
        value: Any,
        subject_pseudonym: str | None = None,
    ) -> None:
        """Set a cached entry with optional subject metadata."""
        self._cache[cache_key] = {
            "value": value,
            "subject_pseudonym": subject_pseudonym,
        }

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        """Evict all cache keys associated with subject pseudonym."""
        keys_to_remove = [
            k
            for k, v in self._cache.items()
            if v.get("subject_pseudonym") == subject_pseudonym or subject_pseudonym in k
        ]
        for k in keys_to_remove:
            self._cache.pop(k, None)

        return PurgeTarget(
            surface_name=self.surface_name,
            surface_type=self.surface_type,
            status="purged",
            rows_affected=len(keys_to_remove),
            files_affected=0,
            purged_at=datetime.now(UTC),
        )

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        """Canary scan for remaining cache entries referencing pseudonym."""
        return [
            k
            for k, v in self._cache.items()
            if v.get("subject_pseudonym") == subject_pseudonym or subject_pseudonym in k
        ]


class SearchIndexConnector(PurgeConnector):
    """Connector for removing documents from full-text search indexes."""

    def __init__(self, surface_name: str = "search_index") -> None:
        """Initialize SearchIndexConnector with an in-memory document repository."""
        self.surface_name = surface_name
        self.surface_type = "inverted_index"
        self._index: dict[str, dict[str, Any]] = {}  # doc_id -> doc

    def index_document(
        self,
        doc_id: str,
        subject_pseudonym: str,
        content: str,
        purpose: str = "",
    ) -> None:
        """Add a document to the index."""
        self._index[doc_id] = {
            "subject_pseudonym": subject_pseudonym,
            "content": content,
            "purpose": purpose,
        }

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        """Remove indexed documents matching subject pseudonym."""
        docs_to_remove = [
            doc_id
            for doc_id, doc in self._index.items()
            if doc.get("subject_pseudonym") == subject_pseudonym
        ]
        for doc_id in docs_to_remove:
            self._index.pop(doc_id, None)

        return PurgeTarget(
            surface_name=self.surface_name,
            surface_type=self.surface_type,
            status="purged",
            rows_affected=len(docs_to_remove),
            files_affected=0,
            purged_at=datetime.now(UTC),
        )

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        """Canary scan for remaining indexed documents referencing pseudonym."""
        return [
            doc_id
            for doc_id, doc in self._index.items()
            if doc.get("subject_pseudonym") == subject_pseudonym
        ]


class LogConnector(PurgeConnector):
    """Connector for redacting subject identifiers in log streams.

    Note on Architectural Limitation:
    In strict append-only log architecture, personal data is redacted in-place or masked
    (e.g., HMAC pseudonym replaces plain identifiers) with cryptographic irreversibility.
    Physical log deletion is bounded by append-only immutability.
    """

    def __init__(self, surface_name: str = "logs") -> None:
        """Initialize LogConnector with an in-memory log buffer."""
        self.surface_name = surface_name
        self.surface_type = "append_log"
        self._logs: list[dict[str, Any]] = []

    def append_log(
        self,
        entry_id: str,
        message: str,
        subject_pseudonym: str | None = None,
    ) -> None:
        """Append a log entry."""
        self._logs.append(
            {
                "entry_id": entry_id,
                "message": message,
                "subject_pseudonym": subject_pseudonym,
                "redacted": False,
            }
        )

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        """Redact occurrences of subject pseudonym in log entries."""
        redacted_count = 0
        for entry in self._logs:
            modified = False
            if entry.get("subject_pseudonym") == subject_pseudonym:
                entry["subject_pseudonym"] = "[REDACTED_BY_ATHAR]"
                modified = True
            if subject_pseudonym in entry.get("message", ""):
                entry["message"] = entry["message"].replace(
                    subject_pseudonym, "[REDACTED_BY_ATHAR]"
                )
                modified = True
            if modified:
                entry["redacted"] = True
                redacted_count += 1

        return PurgeTarget(
            surface_name=self.surface_name,
            surface_type=self.surface_type,
            status="purged",
            rows_affected=redacted_count,
            files_affected=0,
            purged_at=datetime.now(UTC),
        )

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        """Canary scan for unredacted appearances of pseudonym in logs."""
        remnants: list[str] = []
        for entry in self._logs:
            if entry.get(
                "subject_pseudonym"
            ) == subject_pseudonym or subject_pseudonym in entry.get("message", ""):
                remnants.append(str(entry.get("entry_id")))
        return remnants


FilestoreConnector = FileStoreConnector
