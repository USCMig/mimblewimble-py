from abc import ABC, abstractmethod
from pathlib import Path
import sqlite3
import threading
from typing import Dict, Optional

from mimblewimble.blockchain import BlockHeader
from mimblewimble.serializer import Serializer


class IBlockDB(ABC):
    """Interface that DifficultyCalculator / DifficultyLoader expects"""

    @abstractmethod
    def get_block_header(self, block_hash: str) -> Optional[BlockHeader]:
        """Return header by its hash or None if not found"""
        pass

    # Optional: useful for testing / debugging
    @abstractmethod
    def get_header_by_height(self, height: int) -> Optional[BlockHeader]:
        """Optional – not required by difficulty logic, but helpful"""
        pass

    def get_best_header(self) -> Optional[BlockHeader]:
        """Return the header with the greatest total difficulty, if known."""
        return None


class InMemoryBlockDB(IBlockDB):
    """
    Simple in-memory block database for unit tests
    Stores headers by hash + optional height index
    """

    def __init__(self):
        # hash → BlockHeader
        self.by_hash: Dict[str, BlockHeader] = {}
        # height → hash (for optional height lookups)
        self.by_height: Dict[int, str] = {}

    def add_header(self, header: BlockHeader):
        """Add or overwrite a header"""
        self.by_hash[header.getHash().hex()] = header
        self.by_height[header.getHeight()] = header.getHash().hex()

    def get_block_header(self, block_hash: str) -> Optional[BlockHeader]:
        return self.by_hash.get(block_hash)

    def get_header_by_height(self, height: int) -> Optional[BlockHeader]:
        h = self.by_height.get(height)
        if h is None:
            return None
        return self.by_hash.get(h)

    def get_best_header(self) -> Optional[BlockHeader]:
        if not self.by_hash:
            return None
        return max(
            self.by_hash.values(),
            key=lambda header: (header.getTotalDifficulty(), header.getHeight()),
        )

    def clear(self):
        """Reset database – useful between tests"""
        self.by_hash.clear()
        self.by_height.clear()

    def size(self) -> int:
        return len(self.by_hash)


class SQLiteBlockDB(IBlockDB):
    """Persistent block-header store backed by SQLite.

    The database stores serialized headers by hash and maintains a height index
    for locator construction. SQLite is part of Python's standard library, so
    this backend is suitable as the default durable node storage primitive.
    """

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS block_headers (
                    hash_hex TEXT PRIMARY KEY,
                    height INTEGER NOT NULL,
                    total_difficulty INTEGER NOT NULL,
                    raw BLOB NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_block_headers_height "
                "ON block_headers(height)"
            )

    @staticmethod
    def _serialize(header: BlockHeader) -> bytes:
        serializer = Serializer()
        header.serialize(serializer)
        return serializer.getvalue()

    @staticmethod
    def _deserialize(raw: bytes) -> BlockHeader:
        serializer = Serializer()
        serializer.write(raw)
        return BlockHeader.deserialize(serializer)

    def add_header(self, header: BlockHeader) -> None:
        raw = self._serialize(header)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO block_headers (hash_hex, height, total_difficulty, raw)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hash_hex) DO UPDATE SET
                    height = excluded.height,
                    total_difficulty = excluded.total_difficulty,
                    raw = excluded.raw
                """,
                (
                    header.getHash().hex(),
                    header.getHeight(),
                    header.getTotalDifficulty(),
                    raw,
                ),
            )

    def _get_one(self, query: str, params: tuple) -> Optional[BlockHeader]:
        with self._lock:
            row = self._conn.execute(query, params).fetchone()
        return self._deserialize(bytes(row[0])) if row is not None else None

    def get_block_header(self, block_hash: str) -> Optional[BlockHeader]:
        return self._get_one(
            "SELECT raw FROM block_headers WHERE hash_hex = ?", (block_hash,)
        )

    def get_header_by_height(self, height: int) -> Optional[BlockHeader]:
        return self._get_one(
            "SELECT raw FROM block_headers WHERE height = ? "
            "ORDER BY total_difficulty DESC LIMIT 1",
            (height,),
        )

    def get_best_header(self) -> Optional[BlockHeader]:
        return self._get_one(
            "SELECT raw FROM block_headers "
            "ORDER BY total_difficulty DESC, height DESC LIMIT 1",
            (),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
