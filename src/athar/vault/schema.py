"""SQLite schema definitions and Data Access Objects (DAOs) for the Athar vault.

Defines persistence tables:
- subjects: Pseudonyms, blind index mappings, active DEK references
- records: Encrypted data records with AAD and nonces
- keys: Three-tier key records at rest with wrapping relationships
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class EncryptedRecord:
    """Encrypted record containing ciphertext, cryptographic nonce, and AAD."""

    record_id: str
    subject_pseudonym: str
    purpose: str
    ciphertext: bytes
    nonce: bytes
    aad: bytes
    dek_id: str
    created_at: datetime


@dataclass
class SubjectRecord:
    """Subject identity record linking pseudonym and blind index."""

    pseudonym: str
    blind_index: str | None = None
    purpose_id: str | None = None
    dek_id: str | None = None


@dataclass
class KeyRecord:
    """Persisted cryptographic key record."""

    id: str
    tier: str
    status: str
    wrapped_material: bytes
    parent_key_id: str | None = None
    purpose: str | None = None
    period: str | None = None
    subject_pseudonym: str | None = None
    created_at: str = ""
    scheduled_destruction: str | None = None
    destroyed_at: str | None = None


def create_tables(conn: sqlite3.Connection) -> None:
    """Initialize SQLite database schema for Athar vault and keystore.

    Args:
        conn: An open sqlite3 Connection.
    """
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS subjects (
        pseudonym TEXT PRIMARY KEY,
        blind_index TEXT UNIQUE,
        purpose_id TEXT,
        dek_id TEXT
    );

    CREATE TABLE IF NOT EXISTS keys (
        id TEXT PRIMARY KEY,
        tier TEXT NOT NULL,
        status TEXT NOT NULL,
        wrapped_material BLOB NOT NULL,
        parent_key_id TEXT,
        purpose TEXT,
        period TEXT,
        subject_pseudonym TEXT,
        created_at TEXT NOT NULL,
        scheduled_destruction TEXT,
        destroyed_at TEXT,
        FOREIGN KEY (parent_key_id) REFERENCES keys(id)
    );

    CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY,
        subject_pseudonym TEXT,
        purpose TEXT,
        ciphertext BLOB NOT NULL,
        nonce BLOB NOT NULL,
        aad BLOB NOT NULL,
        dek_id TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (subject_pseudonym) REFERENCES subjects(pseudonym)
    );

    CREATE INDEX IF NOT EXISTS idx_records_subject ON records(subject_pseudonym);
    CREATE INDEX IF NOT EXISTS idx_records_dek ON records(dek_id);
    CREATE INDEX IF NOT EXISTS idx_keys_parent ON keys(parent_key_id);
    CREATE INDEX IF NOT EXISTS idx_subjects_blind_index ON subjects(blind_index);
    """)
    conn.commit()


class SubjectStore:
    """Data Access Object for the `subjects` table."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        """Initialize SubjectStore with a database connection."""
        self._conn = conn

    def insert(
        self,
        pseudonym: str,
        blind_index: str | None = None,
        purpose_id: str | None = None,
        dek_id: str | None = None,
    ) -> SubjectRecord:
        """Insert a new subject record.

        Args:
            pseudonym: Unique pseudonym for the subject.
            blind_index: Optional hex blind index for privacy queries.
            purpose_id: Optional purpose identifier.
            dek_id: Optional DEK UUID currently assigned.

        Returns:
            The created SubjectRecord.
        """
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO subjects (pseudonym, blind_index, purpose_id, dek_id)
            VALUES (?, ?, ?, ?)
            """,
            (pseudonym, blind_index, purpose_id, dek_id),
        )
        self._conn.commit()
        return SubjectRecord(
            pseudonym=pseudonym,
            blind_index=blind_index,
            purpose_id=purpose_id,
            dek_id=dek_id,
        )

    def upsert(
        self,
        pseudonym: str,
        blind_index: str | None = None,
        purpose_id: str | None = None,
        dek_id: str | None = None,
    ) -> SubjectRecord:
        """Insert or update a subject record."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO subjects (pseudonym, blind_index, purpose_id, dek_id)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(pseudonym) DO UPDATE SET
                blind_index = COALESCE(excluded.blind_index, subjects.blind_index),
                purpose_id = COALESCE(excluded.purpose_id, subjects.purpose_id),
                dek_id = COALESCE(excluded.dek_id, subjects.dek_id)
            """,
            (pseudonym, blind_index, purpose_id, dek_id),
        )
        self._conn.commit()
        return self.get(pseudonym)  # type: ignore[return-value]

    def get(self, pseudonym: str) -> SubjectRecord | None:
        """Fetch subject record by pseudonym."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT pseudonym, blind_index, purpose_id, dek_id FROM subjects WHERE pseudonym = ?",
            (pseudonym,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return SubjectRecord(
            pseudonym=row[0],
            blind_index=row[1],
            purpose_id=row[2],
            dek_id=row[3],
        )

    def get_by_blind_index(self, blind_index: str) -> SubjectRecord | None:
        """Fetch subject record by exact blind index lookup."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT pseudonym, blind_index, purpose_id, dek_id FROM subjects WHERE blind_index = ?",
            (blind_index,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return SubjectRecord(
            pseudonym=row[0],
            blind_index=row[1],
            purpose_id=row[2],
            dek_id=row[3],
        )

    def update(
        self,
        pseudonym: str,
        blind_index: str | None = None,
        purpose_id: str | None = None,
        dek_id: str | None = None,
    ) -> bool:
        """Update fields on a subject record."""
        updates: list[str] = []
        params: list[str | None] = []

        if blind_index is not None:
            updates.append("blind_index = ?")
            params.append(blind_index)
        if purpose_id is not None:
            updates.append("purpose_id = ?")
            params.append(purpose_id)
        if dek_id is not None:
            updates.append("dek_id = ?")
            params.append(dek_id)

        if not updates:
            return False

        params.append(pseudonym)
        # nosec B608 - the SET clause is built only from the fixed fragments above;
        # every value is bound as a parameter.
        sql = f"UPDATE subjects SET {', '.join(updates)} WHERE pseudonym = ?"  # nosec B608
        cursor = self._conn.cursor()
        cursor.execute(sql, tuple(params))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete(self, pseudonym: str) -> bool:
        """Delete subject record by pseudonym."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM subjects WHERE pseudonym = ?", (pseudonym,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self) -> list[SubjectRecord]:
        """List all subject records."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT pseudonym, blind_index, purpose_id, dek_id FROM subjects")
        rows = cursor.fetchall()
        return [
            SubjectRecord(pseudonym=r[0], blind_index=r[1], purpose_id=r[2], dek_id=r[3])
            for r in rows
        ]


class RecordStore:
    """Data Access Object for the `records` table."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        """Initialize RecordStore with a database connection."""
        self._conn = conn

    def insert(self, record: EncryptedRecord) -> None:
        """Insert an encrypted record into the database."""
        cursor = self._conn.cursor()
        created_str = (
            record.created_at.isoformat()
            if isinstance(record.created_at, datetime)
            else str(record.created_at)
        )
        cursor.execute(
            """
            INSERT INTO records (id, subject_pseudonym, purpose, ciphertext, nonce, aad, dek_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.record_id,
                record.subject_pseudonym,
                record.purpose,
                record.ciphertext,
                record.nonce,
                record.aad,
                record.dek_id,
                created_str,
            ),
        )
        self._conn.commit()

    def get(self, record_id: str) -> EncryptedRecord | None:
        """Fetch an encrypted record by its ID."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, subject_pseudonym, purpose, ciphertext, nonce, aad, dek_id, created_at
            FROM records WHERE id = ?
            """,
            (record_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        created_dt = (
            datetime.fromisoformat(row[7]) if isinstance(row[7], str) else datetime.now(UTC)
        )
        return EncryptedRecord(
            record_id=row[0],
            subject_pseudonym=row[1],
            purpose=row[2],
            ciphertext=row[3],
            nonce=row[4],
            aad=row[5],
            dek_id=row[6],
            created_at=created_dt,
        )

    def list_by_subject(self, subject_pseudonym: str) -> list[EncryptedRecord]:
        """List all encrypted records belonging to a subject pseudonym."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, subject_pseudonym, purpose, ciphertext, nonce, aad, dek_id, created_at
            FROM records WHERE subject_pseudonym = ?
            """,
            (subject_pseudonym,),
        )
        rows = cursor.fetchall()
        result: list[EncryptedRecord] = []
        for row in rows:
            created_dt = (
                datetime.fromisoformat(row[7]) if isinstance(row[7], str) else datetime.now(UTC)
            )
            result.append(
                EncryptedRecord(
                    record_id=row[0],
                    subject_pseudonym=row[1],
                    purpose=row[2],
                    ciphertext=row[3],
                    nonce=row[4],
                    aad=row[5],
                    dek_id=row[6],
                    created_at=created_dt,
                )
            )
        return result

    def delete(self, record_id: str) -> bool:
        """Delete an encrypted record by ID."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM records WHERE id = ?", (record_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self) -> list[EncryptedRecord]:
        """List all encrypted records in the store."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT id, subject_pseudonym, purpose, ciphertext, nonce, aad, dek_id, created_at FROM records"
        )
        rows = cursor.fetchall()
        result: list[EncryptedRecord] = []
        for row in rows:
            created_dt = (
                datetime.fromisoformat(row[7]) if isinstance(row[7], str) else datetime.now(UTC)
            )
            result.append(
                EncryptedRecord(
                    record_id=row[0],
                    subject_pseudonym=row[1],
                    purpose=row[2],
                    ciphertext=row[3],
                    nonce=row[4],
                    aad=row[5],
                    dek_id=row[6],
                    created_at=created_dt,
                )
            )
        return result


class KeyStore:
    """Data Access Object for the `keys` table in SQLite."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        """Initialize KeyStore with a database connection."""
        self._conn = conn

    def insert(
        self,
        key_id: str,
        tier: str,
        status: str,
        wrapped_material: bytes,
        parent_key_id: str | None = None,
        purpose: str | None = None,
        period: str | None = None,
        subject_pseudonym: str | None = None,
        created_at: str | None = None,
        scheduled_destruction: str | None = None,
        destroyed_at: str | None = None,
    ) -> KeyRecord:
        """Insert a cryptographic key record into the database."""
        created_str = created_at or datetime.now(UTC).isoformat()
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO keys (
                id, tier, status, wrapped_material, parent_key_id,
                purpose, period, subject_pseudonym, created_at,
                scheduled_destruction, destroyed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_id,
                tier,
                status,
                wrapped_material,
                parent_key_id,
                purpose,
                period,
                subject_pseudonym,
                created_str,
                scheduled_destruction,
                destroyed_at,
            ),
        )
        self._conn.commit()
        return KeyRecord(
            id=key_id,
            tier=tier,
            status=status,
            wrapped_material=wrapped_material,
            parent_key_id=parent_key_id,
            purpose=purpose,
            period=period,
            subject_pseudonym=subject_pseudonym,
            created_at=created_str,
            scheduled_destruction=scheduled_destruction,
            destroyed_at=destroyed_at,
        )

    def get(self, key_id: str) -> KeyRecord | None:
        """Fetch a key record by ID."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, tier, status, wrapped_material, parent_key_id,
                   purpose, period, subject_pseudonym, created_at,
                   scheduled_destruction, destroyed_at
            FROM keys WHERE id = ?
            """,
            (key_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return KeyRecord(
            id=row[0],
            tier=row[1],
            status=row[2],
            wrapped_material=row[3],
            parent_key_id=row[4],
            purpose=row[5],
            period=row[6],
            subject_pseudonym=row[7],
            created_at=row[8],
            scheduled_destruction=row[9],
            destroyed_at=row[10],
        )

    def update_status(
        self,
        key_id: str,
        status: str,
        destroyed_at: str | None = None,
        scheduled_destruction: str | None = None,
    ) -> bool:
        """Update key status and destruction timestamps."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            UPDATE keys
            SET status = ?,
                destroyed_at = COALESCE(?, destroyed_at),
                scheduled_destruction = COALESCE(?, scheduled_destruction)
            WHERE id = ?
            """,
            (status, destroyed_at, scheduled_destruction, key_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def update_material(self, key_id: str, wrapped_material: bytes) -> bool:
        """Overwrite key material (e.g. during simulated destruction)."""
        cursor = self._conn.cursor()
        cursor.execute(
            "UPDATE keys SET wrapped_material = ? WHERE id = ?",
            (wrapped_material, key_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def delete(self, key_id: str) -> bool:
        """Delete key record by ID."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM keys WHERE id = ?", (key_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_children(self, parent_key_id: str) -> list[KeyRecord]:
        """List all child keys wrapped by parent_key_id."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, tier, status, wrapped_material, parent_key_id,
                   purpose, period, subject_pseudonym, created_at,
                   scheduled_destruction, destroyed_at
            FROM keys WHERE parent_key_id = ?
            """,
            (parent_key_id,),
        )
        rows = cursor.fetchall()
        return [
            KeyRecord(
                id=r[0],
                tier=r[1],
                status=r[2],
                wrapped_material=r[3],
                parent_key_id=r[4],
                purpose=r[5],
                period=r[6],
                subject_pseudonym=r[7],
                created_at=r[8],
                scheduled_destruction=r[9],
                destroyed_at=r[10],
            )
            for r in rows
        ]

    def list_all(self) -> list[KeyRecord]:
        """List all key records."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, tier, status, wrapped_material, parent_key_id,
                   purpose, period, subject_pseudonym, created_at,
                   scheduled_destruction, destroyed_at
            FROM keys
            """
        )
        rows = cursor.fetchall()
        return [
            KeyRecord(
                id=r[0],
                tier=r[1],
                status=r[2],
                wrapped_material=r[3],
                parent_key_id=r[4],
                purpose=r[5],
                period=r[6],
                subject_pseudonym=r[7],
                created_at=r[8],
                scheduled_destruction=r[9],
                destroyed_at=r[10],
            )
            for r in rows
        ]
