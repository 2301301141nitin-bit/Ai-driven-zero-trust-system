"""
Database module for MongoDB integration with in-memory fallback.

When MONGODB_URI is not set, all data is stored in-memory so the system
works out-of-the-box without any external database.
"""
from __future__ import annotations

import os
import threading
from collections import defaultdict
from datetime import datetime
from typing import Any

_MONGODB_URI = os.getenv("MONGODB_URI", "")

# --------------------------------------------------------------------------- #
# In-memory store (used when MongoDB is not configured)                       #
# --------------------------------------------------------------------------- #

class _InMemoryCollection:
    """Minimal dict-backed collection that mimics the PyMongo collection API."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._docs: list[dict[str, Any]] = []

    def insert_one(self, document: dict[str, Any]) -> None:
        with self._lock:
            doc = dict(document)
            if "_id" not in doc:
                doc["_id"] = len(self._docs)
            self._docs.append(doc)

    def find(self, query: dict | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if not query:
                # Return copies of documents to avoid callers mutating internal state.
                return [dict(doc) for doc in self._docs]
            result = []
            for doc in self._docs:
                if all(doc.get(k) == v for k, v in query.items()):
                    result.append(dict(doc))
            return result

    def find_one(self, query: dict) -> dict[str, Any] | None:
        with self._lock:
            for doc in self._docs:
                if all(doc.get(k) == v for k, v in query.items()):
                    return dict(doc)
            return None

    def update_one(self, query: dict, update: dict, upsert: bool = False) -> None:
        with self._lock:
            set_vals = update.get("$set", {})
            for doc in self._docs:
                if all(doc.get(k) == v for k, v in query.items()):
                    doc.update(set_vals)
                    return
            if upsert:
                new_doc = {**query, **set_vals, "_id": len(self._docs)}
                self._docs.append(new_doc)

    def count_documents(self, query: dict | None = None) -> int:
        return len(self.find(query))


class _InMemoryDB:
    def __init__(self) -> None:
        self._collections: dict[str, _InMemoryCollection] = defaultdict(
            _InMemoryCollection
        )

    def __getitem__(self, name: str) -> _InMemoryCollection:
        return self._collections[name]

    def __getattr__(self, name: str) -> _InMemoryCollection:
        return self._collections[name]


# --------------------------------------------------------------------------- #
# Public helpers                                                               #
# --------------------------------------------------------------------------- #

_db_instance: Any = None


def get_db() -> Any:
    """Return the active database handle (MongoDB or in-memory)."""
    global _db_instance
    if _db_instance is not None:
        return _db_instance

    if _MONGODB_URI:
        try:
            from pymongo import MongoClient  # type: ignore

            client = MongoClient(_MONGODB_URI, serverSelectionTimeoutMS=3000)
            client.admin.command("ping")  # verify connection
            _db_instance = client["zero_trust_db"]
            print("[DB] Connected to MongoDB Atlas.")
        except Exception as exc:  # noqa: BLE001
            print(f"[DB] MongoDB unavailable ({exc}). Falling back to in-memory store.")
            _db_instance = _InMemoryDB()
    else:
        print("[DB] MONGODB_URI not set. Using in-memory store.")
        _db_instance = _InMemoryDB()

    return _db_instance
