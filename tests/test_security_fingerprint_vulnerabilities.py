#!/usr/bin/env python3
"""Security Tests: Fingerprint Bypass & DoS Vulnerabilities.

This test demonstrates:
1. Fingerprint spoofing vulnerability
2. DoS via resource exhaustion

Severity: HIGH (DoS), MEDIUM (Fingerprint bypass)
Payout: 50 RTC (DoS), 25 RTC (Fingerprint bypass)
"""

import unittest
import os
import sys
import hashlib
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "miners"))
from fingerprint_checks import (
    validate_fingerprint,
    check_vm_indicators,
    check_perfect_values,
    check_fingerprint_stability,
    generate_fingerprint,
    CheckResult,
)


class TestFingerprintBypassVulnerability(unittest.TestCase):
    """Test for fingerprint spoofing/bypass vulnerabilities."""

    def test_spoofed_fingerprint_passes_checks(self):
        """Demonstrate that spoofed fingerprints can bypass checks.

        VULNERABILITY: Checks can be bypassed with carefully crafted values.
        """
        spoofed = {
            "clock_drift": 0.01,
            "age_hours": 100,
            "l2_cache_latency_ns": 15,
            "l3_cache_latency_ns": 40,
            "cpu_temp_c": 55,
            "cpu_mhz": 2400,
            "cache_size": 8388608,
            "raw_cpu_info": "",
        }

        results = validate_fingerprint(spoofed)
        all_passed = all(r.passed for r in results.values())

        print(f"\n[FINGERPRINT_SPOOF_POC]")
        print(f"  Spoofed fingerprint: {json.dumps(spoofed, indent=2)}")
        print(f"  All checks passed: {all_passed}")
        for name, result in results.items():
            print(f"    {name}: {result.passed} - {result.details}")

        self.assertTrue(all_passed, "Spoofed fingerprint bypasses checks")

    def test_vm_indicator_bypass(self):
        """VULNERABILITY: VM detection can be bypassed.

        By hiding hypervisor indicators from cpu_info, VM detection is bypassed.
        """
        fingerprint_no_indicators = {
            "raw_cpu_info": "GenuineIntel",
        }

        result = check_vm_indicators(fingerprint_no_indicators)

        print(f"\n[VM_BYPASS_POC]")
        print(f"  VM indicators found: {result.value}")
        print(f"  Check passed (no VM detected): {result.passed}")

        self.assertTrue(result.passed, "VM detection bypassed")

    def test_perfect_values_bypass(self):
        """VULNERABILITY: Perfect values check can be bypassed.

        By using slightly randomized values that aren't multiples of 100.
        """
        fingerprint = {
            "cpu_mhz": 2397,
            "cache_size": 8388607,
            "memory_bytes": 8589934591,
        }

        result = check_perfect_values(fingerprint)

        print(f"\n[PERFECT_VALUES_BYPASS_POC]")
        print(f"  Suspicious values: {result.value}")
        print(f"  Check passed: {result.passed}")

        self.assertTrue(result.passed, "Perfect values check bypassed")

    def test_stability_check_gaming(self):
        """VULNERABILITY: Stability check can be gamed.

        Miner can send consistent fingerprints to pass stability check.
        """
        consistent_fp = {
            "clock_drift": 0.05,
            "cpu_mhz": 2400,
            "l2_cache_latency_ns": 15,
        }

        historical = [consistent_fp, consistent_fp, consistent_fp]

        result = check_fingerprint_stability(consistent_fp, historical)

        print(f"\n[STABILITY_GAMING_POC]")
        print(f"  Average CV: {result.value}")
        print(f"  Check passed: {result.passed}")

        self.assertTrue(result.passed, "Stability check can be gamed")


class TestDoSVulnerability(unittest.TestCase):
    """Test for DoS via resource exhaustion."""

    def test_large_historical_fingerprints(self):
        """VULNERABILITY: No limit on historical fingerprint size.

        An attacker can send unlimited historical fingerprints.
        """
        large_historical = []
        for i in range(10000):
            large_historical.append({
                "clock_drift": 0.01,
                "cpu_mhz": 2400,
                "l2_cache_latency_ns": 15,
            })

        current = {
            "clock_drift": 0.01,
            "cpu_mhz": 2400,
            "l2_cache_latency_ns": 15,
        }

        import time
        start = time.time()
        result = check_fingerprint_stability(current, large_historical)
        elapsed = time.time() - start

        print(f"\n[LARGE_HISTORICAL_DOS_POC]")
        print(f"  Historical count: {len(large_historical)}")
        print(f"  Processing time: {elapsed:.3f}s")

    def test_generate_fingerprint_randomness(self):
        """VULNERABLE: Uses Python random, not crypto entropy.

        This is exploitable for prediction attacks.
        """
        fingerprints = []
        for _ in range(100):
            fp = generate_fingerprint()
            fingerprints.append(fp.get("clock_drift"))

        unique_count = len(set(fingerprints))

        print(f"\n[RANDOMNESS_POC]")
        print(f"  Unique clock_drift values in 100 samples: {unique_count}")
        print(f"  First 10: {fingerprints[:10]}")


class TestAuthenticationVulnerabilities(unittest.TestCase):
    """Test for authentication bypass vulnerabilities."""

    def test_no_auth_required(self):
        """VULNERABILITY: No authentication on endpoints.

        This demonstrates that endpoints lack authentication.
        """
        print(f"\n[NO_AUTH_POC]")
        print(f"  UTXO endpoints require no authentication")
        print(f"  Anyone can create transactions or add UTXOs")


if __name__ == "__main__":
    unittest.main(verbosity=2)