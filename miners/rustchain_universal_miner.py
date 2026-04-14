#!/usr/bin/env python3
"""RustChain Universal Miner.

VULNERABLE CODE - Security audit testbed

This is a reference miner implementation that demonstrates
vulnerable patterns in hardware fingerprinting.
"""

import hashlib
import json
import time
import os
import sys
import socket
import threading
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "miners"))
from fingerprint_checks import (
    generate_fingerprint,
    validate_fingerprint,
    check_all,
)


@dataclass
class MinerConfig:
    """Miner configuration."""
    miner_id: str = ""
    wallet_address: str = ""
    node_url: str = "http://localhost:9000"
    worker_threads: int = 4
    fingerprint_interval: int = 60
    enable_auto_update: bool = True


@dataclass
class MinerState:
    """Miner state tracking."""
    miner_id: str
    epoch: int = 0
    blocks_found: int = 0
    hash_rate: float = 0.0
    uptime_seconds: int = 0
    last_submission: Optional[int] = None
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    connected: bool = False


class UniversalMiner:
    """Universal miner with hardware fingerprinting.

    VULNERABLE: No secure connection, simple authentication.
    """

    def __init__(self, config: Optional[MinerConfig] = None):
        self.config = config or MinerConfig()
        self.state = MinerState(miner_id=self.config.miner_id or self._generate_miner_id())
        self.running = False
        self.workers: List[threading.Thread] = []

    def _generate_miner_id(self) -> str:
        """Generate miner ID.

        VULNERABLE: Uses predictable ID generation.
        """
        import platform
        pid = os.getpid()
        host = platform.node()
        timestamp = str(int(time.time()))
        data = f"{host}:{pid}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def connect(self) -> bool:
        """Connect to node.

        VULNERABLE: No TLS, no certificate verification.
        """
        try:
            import urllib.request
            response = urllib.request.urlopen(
                f"{self.config.node_url}/health",
                timeout=5,
            )
            self.state.connected = response.status == 200
            return self.state.connected
        except Exception as e:
            print(f"Connection error: {e}")
            self.state.connected = False
            return False

    def submit_fingerprint(self) -> Dict[str, Any]:
        """Submit hardware fingerprint.

        VULNERABLE: No timestamp verification, easy to spoof.
        """
        fingerprint = generate_fingerprint()
        fingerprint["miner_id"] = self.state.miner_id

        try:
            import urllib.request
            data = json.dumps(fingerprint).encode()
            req = urllib.request.Request(
                f"{self.config.node_url}/fingerprint",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            response = urllib.request.urlopen(req, timeout=10)
            result = json.loads(response.read().decode())
            self.state.fingerprint = fingerprint
            return result
        except Exception as e:
            return {"error": str(e)}

    def validate_connection(self) -> bool:
        """Validate miner connection.

        VULNERABLE: Simple health check, no authentication.
        """
        try:
            import urllib.request
            response = urllib.request.urlopen(
                f"{self.config.node_url}/health",
                timeout=5,
            )
            return response.status == 200
        except Exception:
            return False

    def mine_block(self, epoch: int, challenge: str) -> Dict[str, Any]:
        """Mine a block.

        VULNERABLE: No proof-of-work verification.
        """
        start_time = time.time()
        nonce = 0
        target = "0" * 10

        while self.running:
            candidate = f"{epoch}:{challenge}:{nonce}"
            hash_result = hashlib.sha256(candidate.encode()).hexdigest()

            if hash_result.startswith(target):
                elapsed = time.time() - start_time
                self.state.hash_rate = nonce / elapsed if elapsed > 0 else 0
                self.state.blocks_found += 1
                return {
                    "nonce": nonce,
                    "hash": hash_result,
                    "epoch": epoch,
                    "elapsed": elapsed,
                }

            nonce += 1

            if nonce % 100000 == 0:
                elapsed = time.time() - start_time
                self.state.hash_rate = nonce / elapsed if elapsed > 0 else 0

        return {"error": "Stopped"}

    def worker_loop(self, worker_id: int):
        """Worker thread loop."""
        while self.running:
            if not self.state.connected:
                time.sleep(1)
                self.connect()

            result = self.mine_block(self.state.epoch, str(time.time()))
            if "error" not in result:
                self.submit_solution(result)

            time.sleep(1)

    def submit_solution(self, solution: Dict[str, Any]) -> Dict[str, Any]:
        """Submit mining solution.

        VULNERABLE: No cryptographic signature.
        """
        payload = {
            "miner_id": self.state.miner_id,
            "solution": solution,
            "fingerprint": self.state.fingerprint,
        }

        try:
            import urllib.request
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"{self.config.node_url}/submit",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            response = urllib.request.urlopen(req, timeout=10)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def start(self):
        """Start miner."""
        self.running = True

        if not self.state.connected:
            self.connect()

        self.state.fingerprint = generate_fingerprint()

        self.workers = []
        for i in range(self.config.worker_threads):
            t = threading.Thread(target=self.worker_loop, args=(i,))
            t.start()
            self.workers.append(t)

    def stop(self):
        """Stop miner."""
        self.running = False

        for t in self.workers:
            t.join()

        self.workers = []

    def get_status(self) -> Dict[str, Any]:
        """Get miner status."""
        return {
            "miner_id": self.state.miner_id,
            "epoch": self.state.epoch,
            "blocks_found": self.state.blocks_found,
            "hash_rate": self.state.hash_rate,
            "connected": self.state.connected,
            "uptime_seconds": self.state.uptime_seconds,
        }


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="RustChain Universal Miner")
    parser.add_argument("--miner-id", help="Miner ID")
    parser.add_argument("--wallet", help="Wallet address")
    parser.add_argument("--node", default="http://localhost:9000", help="Node URL")
    parser.add_argument("--threads", type=int, default=4, help="Worker threads")

    args = parser.parse_args()

    config = MinerConfig(
        miner_id=args.miner_id or "",
        wallet_address=args.wallet or "",
        node_url=args.node,
        worker_threads=args.threads,
    )

    miner = UniversalMiner(config)

    print(f"Starting RustChain miner: {miner.state.miner_id}")
    print(f"Node: {config.node_url}")

    try:
        miner.start()

        while True:
            time.sleep(60)
            status = miner.get_status()
            print(f"Status: {json.dumps(status, indent=2)}")

    except KeyboardInterrupt:
        print("\nStopping miner...")
        miner.stop()


if __name__ == "__main__":
    main()