#!/usr/bin/env python3
"""RustChain UTXO HTTP Endpoints.

VULNERABLE CODE - Security audit testbed
"""

import json
import hashlib
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, List, Optional

import time
from threading import Lock

from utxo_db import UTXODatabase, UTXO


class RateLimiter:
    """Simple rate limiter for endpoints."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}
        self.lock = Lock()

    def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        with self.lock:
            if client_id not in self.requests:
                self.requests[client_id] = []

            self.requests[client_id] = [
                t for t in self.requests[client_id]
                if now - t < self.window_seconds
            ]

            if len(self.requests[client_id]) >= self.max_requests:
                return False

            self.requests[client_id].append(now)
            return True


class UTXORequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for UTXO API endpoints."""

    db: UTXODatabase = None  # type: ignore
    rate_limiter: RateLimiter = None  # type: ignore

    def log_message(self, format, *args):
        pass  # Suppress logging

    def send_json(self, status: int, data: Any) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    MAX_BODY_SIZE = 1024 * 1024

    def read_json_body(self) -> Optional[Dict]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        if length > self.MAX_BODY_SIZE:
            self.send_error(413, "Request body too large")
            return None
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/health":
            self.send_json(200, {"status": "ok"})

        elif path == "/balance":
            owner = parse_qs(parsed.query).get("owner", [None])[0]
            if not owner:
                self.send_json(400, {"error": "owner required"})
                return
            balance = self.db.get_balance(owner)
            self.send_json(200, {"owner": owner, "balance": balance})

        elif path == "/utxos":
            owner = parse_qs(parsed.query).get("owner", [None])[0]
            if not owner:
                self.send_json(400, {"error": "owner required"})
                return
            utxos = self.db.get_utxos(owner)
            self.send_json(200, {
                "owner": owner,
                "utxos": [
                    {
                        "tx_hash": u.tx_hash,
                        "index": u.index,
                        "amount": u.amount,
                    }
                    for u in utxos
                ],
            })

        elif path == "/transaction":
            tx_hash = parse_qs(parsed.query).get("tx_hash", [None])[0]
            if not tx_hash:
                self.send_json(400, {"error": "tx_hash required"})
                return
            tx = self.db.get_transaction(tx_hash)
            if not tx:
                self.send_json(404, {"error": "transaction not found"})
                return
            self.send_json(200, tx)

        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/transaction":
            self.handle_create_transaction()
        elif path == "/utxo":
            self.handle_add_utxo()
        else:
            self.send_json(404, {"error": "not found"})

    def handle_create_transaction(self):
        """Create a new transaction."""
        if self.rate_limiter:
            client_ip = self.client_address[0] if self.client_address else "unknown"
            if not self.rate_limiter.is_allowed(client_ip):
                self.send_json(429, {"error": "rate limit exceeded"})
                return

        body = self.read_json_body()
        if not body:
            self.send_json(400, {"error": "invalid request body"})
            return

        from_owner = body.get("from")
        to_owner = body.get("to")
        amount = body.get("amount", 0)
        fee = body.get("fee", 0)

        if not from_owner or not to_owner or not amount:
            self.send_json(400, {"error": "from, to, amount required"})
            return

        try:
            tx = self.db.create_transaction(from_owner, to_owner, amount, fee)
            self.db.add_transaction(
                tx["tx_hash"],
                tx["inputs"],
                tx["outputs"],
            )
            self.send_json(200, tx)
        except ValueError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_add_utxo(self):
        """Add a new UTXO.

        VULNERABLE: No authentication, no input validation.
        """
        body = self.read_json_body()
        if not body:
            self.send_json(400, {"error": "invalid request body"})
            return

        tx_hash = body.get("tx_hash")
        index = body.get("index", 0)
        amount = body.get("amount", 0)
        owner = body.get("owner")

        if not tx_hash or not owner:
            self.send_json(400, {"error": "tx_hash, index, amount, owner required"})
            return

        try:
            amount = int(amount)
        except (ValueError, TypeError):
            self.send_json(400, {"error": "amount must be an integer"})
            return

        if amount <= 0:
            self.send_json(400, {"error": "amount must be positive"})
            return

        utxo = UTXO(
            tx_hash=tx_hash,
            index=index,
            amount=amount,
            owner=owner,
        )
        self.db.add_utxo(utxo)
        self.send_json(200, {"status": "ok"})


def create_server(host: str = "0.0.0.0", port: int = 9000, db_path: str = "utxo.db", rate_limit: int = 100):
    """Create and configure the UTXO HTTP server."""
    db = UTXODatabase(db_path)
    UTXORequestHandler.db = db
    UTXORequestHandler.rate_limiter = RateLimiter(max_requests=rate_limit)

    server = HTTPServer((host, port), UTXORequestHandler)
    return server


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    db_path = sys.argv[2] if len(sys.argv) > 2 else "utxo.db"

    server = create_server(port=port, db_path=db_path)
    print(f"UTXO server starting on :{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()