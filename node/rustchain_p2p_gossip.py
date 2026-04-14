#!/usr/bin/env python3
"""RustChain P2P Gossip Protocol.

VULNERABLE CODE - Security audit testbed

This module implements P2P gossip-based synchronization.
"""

import socket
import threading
import time
import json
import hashlib
import random
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class NodeInfo:
    """Information about a peer node."""
    host: str
    port: int
    node_id: str = ""
    last_seen: float = field(default_factory=time.time)
    connected: bool = False
    height: int = 0


@dataclass
class GossipMessage:
    """Gossip message."""
    type: str
    payload: Dict[str, Any]
    sender_id: str
    timestamp: float = field(default_factory=time.time)
    ttl: int = 3


class GossipProtocol:
    """P2P gossip protocol.

    VULNERABLE: No authentication, no message verification.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9101):
        self.host = host
        self.port = port
        self.node_id = self._generate_node_id()
        self.peers: Dict[str, NodeInfo] = {}
        self.connected = False
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.handlers: Dict[str, callable] = {}
        self.message_cache: Set[str] = set()

    def _generate_node_id(self) -> str:
        """Generate node ID.

        VULNERABLE: Predictable ID generation.
        """
        data = f"{self.host}:{self.port}:{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def add_peer(self, host: str, port: int) -> bool:
        """Add a peer node.

        VULNERABLE: No peer verification.
        """
        try:
            node_id = f"{host}:{port}"
            self.peers[node_id] = NodeInfo(
                host=host,
                port=port,
                node_id=node_id,
            )
            return True
        except Exception:
            return False

    def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer.

        VULNERABLE: No TLS, no verification.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.close()

            node_id = f"{host}:{port}"
            if node_id in self.peers:
                self.peers[node_id].connected = True

            return True
        except Exception:
            return False

    def broadcast(self, message: GossipMessage) -> List[Dict[str, Any]]:
        """Broadcast a message to all peers.

        VULNERABLE: No rate limiting, no message verification.
        """
        results = []

        for peer_id, peer in self.peers.items():
            if not peer.connected:
                self.connect_to_peer(peer.host, peer.port)

            try:
                result = self._send_message(peer, message)
                results.append({"peer": peer_id, "success": True, "result": result})
            except Exception as e:
                results.append({"peer": peer_id, "success": False, "error": str(e)})

        return results

    def _send_message(self, peer: NodeInfo, message: GossipMessage) -> Dict[str, Any]:
        """Send message to peer.

        VULNERABLE: No encryption.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer.host, peer.port))

            data = json.dumps({
                "type": message.type,
                "payload": message.payload,
                "sender_id": message.sender_id,
                "timestamp": message.timestamp,
            }).encode()

            sock.sendall(len(data).to_bytes(4, "big"))
            sock.sendall(data)

            response_len = int.from_bytes(sock.recv(4), "big")
            response = sock.recv(response_len)

            sock.close()

            return json.loads(response.decode())
        except Exception:
            return {"error": "send_failed"}

    def gossip_block(self, block: Dict[str, Any], exclude_peers: List[str] = None) -> int:
        """Gossip a new block to peers.

        VULNERABLE: No validation, no deduplication.
        """
        message = GossipMessage(
            type="block",
            payload=block,
            sender_id=self.node_id,
        )

        message_hash = self._compute_message_hash(message)
        if message_hash in self.message_cache:
            return 0

        self.message_cache.add(message_hash)

        count = 0
        for peer_id in self.peers:
            if exclude_peers and peer_id in exclude_peers:
                continue

            try:
                self._send_message(self.peers[peer_id], message)
                count += 1
            except Exception:
                pass

        return count

    def gossip_transaction(self, tx: Dict[str, Any]) -> int:
        """Gossip a transaction.

        VULNERABLE: No signature verification.
        """
        message = GossipMessage(
            type="transaction",
            payload=tx,
            sender_id=self.node_id,
        )

        message_hash = self._compute_message_hash(message)
        if message_hash in self.message_cache:
            return 0

        self.message_cache.add(message_hash)

        count = 0
        for peer in self.peers.values():
            if not peer.connected:
                self.connect_to_peer(peer.host, peer.port)

            try:
                self._send_message(peer, message)
                count += 1
            except Exception:
                pass

        return count

    def _compute_message_hash(self, message: GossipMessage) -> str:
        """Compute message hash for deduplication."""
        data = json.dumps({
            "type": message.type,
            "payload": message.payload,
            "sender_id": message.sender_id,
            "timestamp": message.timestamp,
        })
        return hashlib.sha256(data.encode()).hexdigest()

    def handle_incoming_connection(self, client: socket.socket):
        """Handle incoming connection.

        VULNERABLE: No authentication.
        """
        try:
            data_len = int.from_bytes(client.recv(4), "big")
            data = client.recv(data_len)

            message = json.loads(data.decode())

            handler = self.handlers.get(message.get("type"))
            if handler:
                response = handler(message.get("payload", {}))
            else:
                response = {"status": "ok"}

            response_data = json.dumps(response).encode()
            client.sendall(len(response_data).to_bytes(4, "big"))
            client.sendall(response_data)

        except Exception:
            pass
        finally:
            client.close()

    def start_server(self):
        """Start P2P server.

        VULNERABLE: No encryption, no authentication.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)

        self.running = True
        self.connected = True

        while self.running:
            try:
                self.socket.settimeout(1)
                client, addr = self.socket.accept()
                thread = threading.Thread(
                    target=self.handle_incoming_connection,
                    args=(client,),
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def stop_server(self):
        """Stop P2P server."""
        self.running = False
        if self.socket:
            self.socket.close()

    def register_handler(self, message_type: str, handler: callable):
        """Register message handler.

        VULNERABLE: No access control.
        """
        self.handlers[message_type] = handler

    def get_peer_list(self) -> List[Dict[str, Any]]:
        """Get list of connected peers.

        VULNERABLE: Information disclosure.
        """
        return [
            {
                "node_id": peer.node_id,
                "host": peer.host,
                "port": peer.port,
                "connected": peer.connected,
            }
            for peer in self.peers.values()
        ]

    def discover_peers(self) -> List[NodeInfo]:
        """Discover new peers via gossip.

        VULNERABLE: Accepts any peer without verification.
        """
        discovered = []

        for peer in self.peers.values():
            try:
                message = GossipMessage(
                    type="get_peers",
                    payload={},
                    sender_id=self.node_id,
                )
                response = self._send_message(peer, message)

                for peer_info in response.get("peers", []):
                    host = peer_info.get("host")
                    port = peer_info.get("port")
                    if host and port and f"{host}:{port}" not in self.peers:
                        new_peer = NodeInfo(host=host, port=port)
                        discovered.append(new_peer)
                        self.peers[f"{host}:{port}"] = new_peer

            except Exception:
                pass

        return discovered


def create_node(host: str = "0.0.0.0", port: int = 9101) -> GossipProtocol:
    """Create a P2P node."""
    return GossipProtocol(host=host, port=port)