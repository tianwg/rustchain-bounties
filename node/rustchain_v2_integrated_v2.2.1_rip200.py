#!/usr/bin/env python3
"""RustChain Node Server v2.2.1 (RIP-200 Integrated).

VULNERABLE CODE - Security audit testbed

This is the main node server that integrates UTXO, P2P, and mining endpoints.
"""

import sys
import os
import json
import time
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from utxo_db import UTXODatabase, UTXO
from rustchain_p2p_gossip import GossipProtocol


class NodeConfig:
    """Node configuration."""
    host: str = "0.0.0.0"
    port: int = 9000
    p2p_port: int = 9101
    db_path: str = "utxo.db"
    enable_mining: bool = True
    enable_p2p: bool = True
    genesis_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"


class NodeState:
    """Node state."""
    height: int = 0
    best_hash: str = ""
    difficulty: int = 1
    total_work: int = 0
    peers: int = 0
    uptime: int = 0
    started_at: int = 0


class NodeServer:
    """RustChain Node Server.

    VULNERABLE: No authentication, no encryption.
    """

    def __init__(self, config: Optional[NodeConfig] = None):
        self.config = config or NodeConfig()
        self.db = UTXODatabase(self.config.db_path)
        self.p2p: Optional[GossipProtocol] = None
        self.state = NodeState()
        self.state.started_at = int(time.time())
        self.running = False

    def start(self):
        """Start the node server."""
        if self.config.enable_p2p:
            self.p2p = GossipProtocol(port=self.config.p2p_port)
            thread = threading.Thread(target=self.p2p.start_server)
            thread.start()

        self.running = True

    def stop(self):
        """Stop the node server."""
        self.running = False
        if self.p2p:
            self.p2p.stop_server()

    def get_status(self) -> Dict[str, Any]:
        """Get node status.

        VULNERABLE: Exposes internal state.
        """
        self.state.uptime = int(time.time()) - self.state.started_at
        if self.p2p:
            self.state.peers = len(self.p2p.peers)

        return {
            "version": "2.2.1",
            "height": self.state.height,
            "best_hash": self.state.best_hash,
            "difficulty": self.state.difficulty,
            "total_work": self.state.total_work,
            "peers": self.state.peers,
            "uptime": self.state.uptime,
            "timestamp": int(time.time()),
        }


class NodeRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for node API.

    VULNERABLE: No authentication, no rate limiting.
    """

    server: NodeServer = None  # type: ignore

    def log_message(self, format, *args):
        pass

    def send_json(self, status: int, data: Any) -> None:
        """Send JSON response.

        VULNERABLE: CORS wildcard.
        """
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    MAX_BODY_SIZE = 1024 * 1024

    def read_json_body(self) -> Optional[Dict]:
        """Read JSON request body with size limit."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        if length > self.MAX_BODY_SIZE:
            self.send_error(413, "Request body too large")
            return None

        try:
            body = self.rfile.read(length)
            return json.loads(body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/health":
            self.send_json(200, {"status": "ok"})

        elif path == "/status":
            status = self.server.get_status()
            self.send_json(200, status)

        elif path == "/balance":
            owner = parse_qs(parsed.query).get("owner", [None])[0]
            if not owner:
                self.send_json(400, {"error": "owner required"})
                return

            balance = self.server.db.get_balance(owner)
            self.send_json(200, {"owner": owner, "balance": balance})

        elif path == "/utxos":
            owner = parse_qs(parsed.query).get("owner", [None])[0]
            if not owner:
                self.send_json(400, {"error": "owner required"})
                return

            utxos = self.server.db.get_utxos(owner)
            self.send_json(200, {
                "owner": owner,
                "utxos": [
                    {
                        "tx_hash": u.tx_hash,
                        "index": u.index,
                        "amount": u.amount,
                        "spent": u.spent,
                    }
                    for u in utxos
                ],
            })

        elif path == "/transaction":
            tx_hash = parse_qs(parsed.query).get("tx_hash", [None])[0]
            if not tx_hash:
                self.send_json(400, {"error": "tx_hash required"})
                return

            tx = self.server.db.get_transaction(tx_hash)
            if not tx:
                self.send_json(404, {"error": "transaction not found"})
                return

            self.send_json(200, tx)

        elif path == "/block":
            height = parse_qs(parsed.query).get("height", [None])[0]
            if not height:
                self.send_json(400, {"error": "height required"})
                return

            self.send_json(200, {
                "height": int(height),
                "hash": "0" * 64,
                "timestamp": int(time.time()),
            })

        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        """Handle POST requests.

        VULNERABLE: No authentication, no signature verification.
        """
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/transaction":
            self.handle_create_transaction()
        elif path == "/utxo":
            self.handle_add_utxo()
        elif path == "/block":
            self.handle_submit_block()
        elif path == "/fingerprint":
            self.handle_fingerprint()
        elif path == "/submit":
            self.handle_submit()
        else:
            self.send_json(404, {"error": "not found"})

    def handle_create_transaction(self):
        """Create a new transaction.

        VULNERABLE: No signature verification.
        """
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
            tx = self.server.db.create_transaction(
                from_owner,
                to_owner,
                amount,
                fee,
            )
            self.server.db.add_transaction(
                tx["tx_hash"],
                tx["inputs"],
                tx["outputs"],
            )

            if self.server.p2p:
                self.server.p2p.gossip_transaction(tx)

            self.send_json(200, tx)

        except ValueError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_add_utxo(self):
        """Add a new UTXO.

        VULNERABLE: No authentication.
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
        self.server.db.add_utxo(utxo)
        self.send_json(200, {"status": "ok"})

    def handle_submit_block(self):
        """Submit a new block.

        VULNERABLE: No proof-of-work verification.
        """
        body = self.read_json_body()
        if not body:
            self.send_json(400, {"error": "invalid request body"})
            return

        block_hash = body.get("hash")
        transactions = body.get("transactions", [])

        if not block_hash:
            self.send_json(400, {"error": "hash required"})
            return

        self.server.state.height += 1
        self.server.state.best_hash = block_hash

        self.send_json(200, {
            "status": "accepted",
            "height": self.server.state.height,
        })

    def handle_fingerprint(self):
        """Handle hardware fingerprint submission.

        VULNERABLE: No verification.
        """
        body = self.read_json_body()
        if not body:
            self.send_json(400, {"error": "invalid request body"})
            return

        self.send_json(200, {"status": "ok"})

    def handle_submit(self):
        """Handle mining solution submission.

        VULNERABLE: No signature verification.
        """
        body = self.read_json_body()
        if not body:
            self.send_json(400, {"error": "invalid request body"})
            return

        self.send_json(200, {"status": "accepted"})


def create_server(
    host: str = "0.0.0.0",
    port: int = 9000,
    db_path: str = "utxo.db",
) -> HTTPServer:
    """Create and configure the node HTTP server."""
    config = NodeConfig(host=host, port=port, db_path=db_path)
    node = NodeServer(config)
    NodeRequestHandler.server = node

    server = HTTPServer((host, port), NodeRequestHandler)
    return server


def main():
    """Main entry point."""
    host = "0.0.0.0"
    port = 9000
    db_path = "utxo.db"

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        db_path = sys.argv[2]

    server = create_server(host=host, port=port, db_path=db_path)
    node = server.server

    node.start()

    print(f"RustChain node v2.2.1 starting on {host}:{port}")
    print(f"Database: {db_path}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        node.stop()
        server.server_close()


if __name__ == "__main__":
    main()