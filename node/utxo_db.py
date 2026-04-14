#!/usr/bin/env python3
"""RustChain UTXO Database Layer.

VULNERABLE CODE - Security audit testbed
"""

import sqlite3
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class UTXO:
    """Unspent Transaction Output."""
    tx_hash: str
    index: int
    amount: int
    owner: str
    script_type: str = "pubkeyhash"
    spent: bool = False
    spent_by: Optional[str] = None


class UTXODatabase:
    """SQLite-based UTXO storage."""

    def __init__(self, db_path: str = "utxo.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS utxo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT NOT NULL,
                indexnum INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                owner TEXT NOT NULL,
                script_type TEXT DEFAULT 'pubkeyhash',
                spent INTEGER DEFAULT 0,
                spent_by TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                UNIQUE(tx_hash, indexnum)
            );
            CREATE INDEX IF NOT EXISTS idx_utxo_owner ON utxo(owner);
            CREATE INDEX IF NOT EXISTS idx_utxo_spent ON utxo(spent);
        """)
        conn.commit()
        conn.close()

    def add_utxo(self, utxo: UTXO) -> int:
        """Add a new UTXO to the database."""
        if utxo.amount <= 0:
            raise ValueError("UTXO amount must be positive")
        conn = self._connect()
        cur = conn.execute(
            """INSERT INTO utxo (tx_hash, indexnum, amount, owner, script_type, spent)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (utxo.tx_hash, utxo.index, utxo.amount, utxo.owner, utxo.script_type),
        )
        conn.commit()
        conn.close()
        return cur.lastrowid

    def get_utxos(self, owner: str) -> List[UTXO]:
        """Get all unspent UTXOs for an owner."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM utxo WHERE owner = ? AND spent = 0 ORDER BY amount DESC",
            (owner,),
        ).fetchall()
        conn.close()
        return [UTXO(
            tx_hash=r["tx_hash"],
            index=r["indexnum"],
            amount=r["amount"],
            owner=r["owner"],
            script_type=r["script_type"],
            spent=bool(r["spent"]),
            spent_by=r["spent_by"],
        ) for r in rows]

    def spend_utxo(self, tx_hash: str, index: int, spent_tx_hash: str) -> bool:
        """Mark a UTXO as spent."""
        conn = self._connect()
        cur = conn.execute(
            "UPDATE utxo SET spent = 1, spent_by = ? WHERE tx_hash = ? AND indexnum = ? AND spent = 0",
            (spent_tx_hash, tx_hash, index),
        )
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def get_balance(self, owner: str) -> int:
        """Get total balance for an owner."""
        conn = self._connect()
        row = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) as balance FROM utxo WHERE owner = ? AND spent = 0",
            (owner,),
        ).fetchone()
        conn.close()
        return row["balance"]

    def create_transaction(
        self,
        from_owner: str,
        to_owner: str,
        amount: int,
        fee: int = 0,
    ) -> Dict[str, Any]:
        """Create a new transaction.

        FIXED: Validate amount and fee are positive.
        """
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if fee < 0:
            raise ValueError("Fee must be non-negative")

        conn = self._connect()

        available = conn.execute(
            "SELECT * FROM utxo WHERE owner = ? AND spent = 0 ORDER BY amount DESC",
            (from_owner,),
        ).fetchall()

        total_available = sum(r["amount"] for r in available)
        if total_available < amount + fee:
            conn.close()
            raise ValueError("Insufficient funds")

        inputs = []
        input_sum = 0
        for row in available:
            if input_sum >= amount + fee:
                break
            inputs.append({
                "tx_hash": row["tx_hash"],
                "index": row["indexnum"],
                "amount": row["amount"],
            })
            input_sum += row["amount"]

        outputs = [{"owner": to_owner, "amount": amount}]
        change = input_sum - amount - fee
        if change > 0:
            outputs.append({"owner": from_owner, "amount": change})
        elif change < 0:
            conn.close()
            raise ValueError("Insufficient funds")

        tx_data = {
            "inputs": inputs,
            "outputs": outputs,
            "timestamp": int(time.time()),
        }
        tx_hash = hashlib.sha256(json.dumps(tx_data).encode()).hexdigest()

        for inp in inputs:
            conn.execute(
                "UPDATE utxo SET spent = 1, spent_by = ? WHERE tx_hash = ? AND indexnum = ?",
                (tx_hash, inp["tx_hash"], inp["index"]),
            )

        conn.commit()
        conn.close()

        return {
            "tx_hash": tx_hash,
            "inputs": inputs,
            "outputs": outputs,
            "fee": fee,
            "timestamp": tx_data["timestamp"],
        }

    def add_transaction(
        self,
        tx_hash: str,
        inputs: List[Dict],
        outputs: List[Dict],
    ) -> None:
        """Add a transaction and create new UTXOs."""
        if not outputs:
            raise ValueError("Transaction must have at least one output")

        for out in outputs:
            amount = out.get("amount")
            if amount is None:
                raise ValueError("Output amount is required")
            if not isinstance(amount, int):
                raise ValueError("Output amount must be an integer")
            if amount <= 0:
                raise ValueError("Output amount must be positive")

        for inp in inputs:
            tx_hash_in = inp.get("tx_hash")
            index = inp.get("index")
            if tx_hash_in is None or index is None:
                raise ValueError("Input tx_hash and index are required")

        conn = self._connect()

        for inp in inputs:
            conn.execute(
                "UPDATE utxo SET spent = 1, spent_by = ? WHERE tx_hash = ? AND indexnum = ?",
                (tx_hash, inp["tx_hash"], inp["index"]),
            )

        for i, out in enumerate(outputs):
            conn.execute(
                "INSERT INTO utxo (tx_hash, indexnum, amount, owner, script_type, spent) VALUES (?, ?, ?, ?, 'pubkeyhash', 0)",
                (tx_hash, i, out["amount"], out["owner"]),
            )

        conn.commit()
        conn.close()

    def get_transaction(self, tx_hash: str) -> Optional[Dict]:
        """Get transaction details."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM utxo WHERE tx_hash = ? OR spent_by = ? ORDER BY indexnum",
            (tx_hash, tx_hash),
        ).fetchall()
        conn.close()
        if not rows:
            return None
        return {
            "tx_hash": tx_hash,
            "utxos": [dict(r) for r in rows],
        }