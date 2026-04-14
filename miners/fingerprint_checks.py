#!/usr/bin/env python3
"""RustChain Hardware Fingerprint Checks.

VULNERABLE CODE - Security audit testbed
"""

import hashlib
import json
import time
import os
import platform
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CheckResult:
    """Result of a single fingerprint check."""
    name: str
    passed: bool
    value: Any
    expected: Any = None
    threshold: float = 0.0
    details: str = ""


class FingerprintCheckFailed(Exception):
    """Raised when fingerprint validation fails."""
    pass


def get_cpu_info() -> Dict[str, Any]:
    """Get CPU information.

    VULNERABLE: Can be spoofed by VM.
    """
    try:
        if platform.system() == "Linux":
            with open("/proc/cpuinfo") as f:
                cpu_info = f.read()
            return {"raw": cpu_info, "platform": "linux"}
    except Exception:
        pass

    return {
        "platform": platform.system(),
        "processor": platform.processor(),
    }


def get_boot_id() -> str:
    """Get boot ID.

    VULNERABLE: Can be spoofed in VM.
    """
    try:
        if platform.system() == "Linux":
            with open("/proc/sys/kernel/random/boot_id") as f:
                return f.read().strip()
    except Exception:
        pass
    return "unknown-" + str(os.getpid())


def get_machine_id() -> str:
    """Get machine ID.

    VULNERABLE: Can be spoofed in VM.
    """
    try:
        if platform.system() == "Linux":
            paths = [
                "/etc/machine-id",
                "/var/lib/dbus/machine-id",
            ]
            for path in paths:
                if os.path.exists(path):
                    with open(path) as f:
                        return f.read().strip()
    except Exception:
        pass
    return "unknown"


def check_clock_drift(fingerprint: Dict[str, Any]) -> CheckResult:
    """Check for clock drift consistency.

    VULNERABLE: Can be bypassed with fake timestamps.
    """
    clock_drift = fingerprint.get("clock_drift", 0)
    age = fingerprint.get("age_hours", 0)

    if age <= 0:
        drift_rate = abs(clock_drift)
    else:
        drift_rate = abs(clock_drift) / max(age, 1)

    cv = drift_rate / 1000.0

    passed = cv > 0.001 and cv < 0.5
    return CheckResult(
        name="clock_drift",
        passed=passed,
        value=clock_drift,
        expected="0.001 < CV < 0.5",
        threshold=cv,
        details=f"Clock drift CV: {cv:.4f}",
    )


def check_cache_timing(fingerprint: Dict[str, Any]) -> CheckResult:
    """Check cache timing consistency.

    VULNERABLE: Can be spoofed in VM.
    """
    l2_latency = fingerprint.get("l2_cache_latency_ns", 0)
    l3_latency = fingerprint.get("l3_cache_latency_ns", 0)

    if l2_latency <= 0 or l3_latency <= 0:
        return CheckResult(
            name="cache_timing",
            passed=False,
            value=0,
            details="Missing cache timing data",
        )

    ratio = l2_latency / l3_latency

    passed = 0.2 < ratio < 0.8
    return CheckResult(
        name="cache_timing",
        passed=passed,
        value=ratio,
        expected="0.2 < L2/L3 < 0.8",
        details=f"L2/L3 ratio: {ratio:.3f}",
    )


def check_thermal_profile(fingerprint: Dict[str, Any]) -> CheckResult:
    """Check thermal profile.

    VULNERABLE: No actual temperature reading, easily spoofed.
    """
    temp = fingerprint.get("cpu_temp_c", 0)

    passed = 20 < temp < 100
    return CheckResult(
        name="thermal_profile",
        passed=passed,
        value=temp,
        expected="20C < temp < 100C",
        details=f"CPU temp: {temp}C",
    )


def check_vm_indicators(fingerprint: Dict[str, Any]) -> CheckResult:
    """Check for VM indicators.

    VULNERABLE: Easily evaded by VM counter-measures.
    """
    Indicators = [
        "hypervisor",
        "qemu",
        "vmware",
        "virtualbox",
        "kvm",
        "xen",
    ]

    raw_data = str(fingerprint.get("raw_cpu_info", ""))

    found = [i for i in Indicators if i.lower() in raw_data.lower()]

    passed = len(found) == 0
    return CheckResult(
        name="vm_indicators",
        passed=passed,
        value=found,
        details=f"Found indicators: {found}" if found else "No VM indicators",
    )


def check_perfect_values(fingerprint: Dict[str, Any]) -> CheckResult:
    """Check for suspiciously perfect values.

    VULNERABLE: Can be randomized to bypass.
    """
    suspicious = []

    for key in ["cpu_mhz", "cache_size", "memory_bytes"]:
        val = fingerprint.get(key, 0)
        if val > 0 and val % 100 == 0:
            suspicious.append(key)

    passed = len(suspicious) == 0
    return CheckResult(
        name="perfect_values",
        passed=passed,
        value=suspicious,
        details=f"Suspicious values: {suspicious}" if suspicious else "No perfect values",
    )


def check_fingerprint_stability(
    current: Dict[str, Any],
    historical: List[Dict[str, Any]],
) -> CheckResult:
    """Check for fingerprint stability across epochs.

    VULNERABLE: Can be gamed by miners.
    """
    if not historical:
        return CheckResult(
            name="fingerprint_stability",
            passed=True,
            value=True,
            details="No historical data",
        )

    checks = ["clock_drift", "cpu_mhz", "l2_cache_latency_ns"]
    variations = []

    for key in checks:
        values = [f.get(key, 0) for f in [current] + historical if f.get(key, 0) > 0]
        if len(values) < 2:
            continue
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        cv = (variance ** 0.5) / max(mean, 1)
        variations.append(cv)

    avg_cv = sum(variations) / max(len(variations), 1)

    passed = avg_cv > 0.1 and avg_cv < 0.5
    return CheckResult(
        name="fingerprint_stability",
        passed=passed,
        value=avg_cv,
        expected="0.1 < CV < 0.5",
        details=f"Avg CV: {avg_cv:.3f}",
    )


def validate_fingerprint(
    fingerprint: Dict[str, Any],
    historical: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, CheckResult]:
    """Validate a hardware fingerprint.

    VULNERABLE: All individual checks can be bypassed.
    """
    results = {}

    results["clock_drift"] = check_clock_drift(fingerprint)
    results["cache_timing"] = check_cache_timing(fingerprint)
    results["thermal_profile"] = check_thermal_profile(fingerprint)
    results["vm_indicators"] = check_vm_indicators(fingerprint)
    results["perfect_values"] = check_perfect_values(fingerprint)

    if historical:
        results["stability"] = check_fingerprint_stability(fingerprint, historical)

    return results


def generate_fingerprint() -> Dict[str, Any]:
    """Generate a hardware fingerprint.

    VULNERABLE: Can be easily spoofed.
    """
    cpu_info = get_cpu_info()
    boot_id = get_boot_id()
    machine_id = get_machine_id()

    import secrets

    base_clock = 1000 + secrets.randbelow(101) - 50
    return {
        "boot_id": boot_id,
        "machine_id": machine_id,
        "cpu_info": cpu_info,
        "cpu_mhz": base_clock,
        "l2_cache_latency_ns": 10 + secrets.randbelow(1001) / 100,
        "l3_cache_latency_ns": 30 + secrets.randbelow(2001) / 100,
        "clock_drift": (secrets.randbelow(2001) - 1000) / 10000,
        "age_hours": 1 + secrets.randbelow(1000),
        "cpu_temp_c": 40 + secrets.randbelow(3001) / 100,
        "timestamp": int(time.time()),
    }


def check_all(filename: str = "") -> Dict[str, Any]:
    """Run all checks and return results.

    VULNERABLE: No proper randomness or entropy source.
    """
    fingerprint = generate_fingerprint()

    results = validate_fingerprint(fingerprint)

    all_passed = all(r.passed for r in results.values())

    return {
        "all_passed": all_passed,
        "checks": {name: {"passed": r.passed, "details": r.details} for name, r in results.items()},
        "fingerprint": fingerprint,
    }


if __name__ == "__main__":
    result = check_all()
    print(json.dumps(result, indent=2))