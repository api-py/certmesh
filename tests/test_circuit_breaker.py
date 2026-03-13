"""Tests for certmesh.circuit_breaker."""

from __future__ import annotations

import time

import pytest

from certmesh.circuit_breaker import create_circuit_breaker
from certmesh.exceptions import CircuitBreakerOpenError


class TestCreateCircuitBreaker:
    def test_invalid_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="failure_threshold"):
            create_circuit_breaker(failure_threshold=0, recovery_timeout_seconds=1)

    def test_invalid_timeout_raises(self) -> None:
        with pytest.raises(ValueError, match="recovery_timeout_seconds"):
            create_circuit_breaker(failure_threshold=1, recovery_timeout_seconds=0)


class TestCircuitBreakerClosed:
    def test_successful_call(self) -> None:
        breaker = create_circuit_breaker(
            failure_threshold=3, recovery_timeout_seconds=10, name="test"
        )

        @breaker
        def ok() -> str:
            return "success"

        assert ok() == "success"

    def test_failure_below_threshold_still_raises(self) -> None:
        breaker = create_circuit_breaker(
            failure_threshold=3, recovery_timeout_seconds=10, name="test"
        )

        @breaker
        def fail() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            fail()
        with pytest.raises(RuntimeError):
            fail()
        # Still below threshold — should raise the original error, not CB error.


class TestCircuitBreakerOpens:
    def test_opens_after_threshold(self) -> None:
        breaker = create_circuit_breaker(
            failure_threshold=2, recovery_timeout_seconds=60, name="test"
        )

        @breaker
        def fail() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            fail()
        with pytest.raises(RuntimeError):
            fail()
        # Now open
        with pytest.raises(CircuitBreakerOpenError):
            fail()


class TestCircuitBreakerRecovery:
    def test_half_open_after_timeout(self) -> None:
        breaker = create_circuit_breaker(
            failure_threshold=1, recovery_timeout_seconds=0.1, name="test"
        )
        call_count = 0

        @breaker
        def flaky() -> str:
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise RuntimeError("fail")
            return "ok"

        with pytest.raises(RuntimeError):
            flaky()

        # Breaker open
        with pytest.raises(CircuitBreakerOpenError):
            flaky()

        # Wait for recovery
        time.sleep(0.15)

        # Should allow a probe call (HALF_OPEN -> succeeds -> CLOSED)
        assert flaky() == "ok"

    def test_half_open_failure_reopens(self) -> None:
        breaker = create_circuit_breaker(
            failure_threshold=1, recovery_timeout_seconds=0.1, name="test"
        )

        @breaker
        def always_fail() -> None:
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError):
            always_fail()

        time.sleep(0.15)

        # Probe call — fails, breaker reopens
        with pytest.raises(RuntimeError):
            always_fail()

        # Should be open again
        with pytest.raises(CircuitBreakerOpenError):
            always_fail()


class TestCircuitBreakerReset:
    def test_success_resets_count(self) -> None:
        breaker = create_circuit_breaker(
            failure_threshold=3, recovery_timeout_seconds=60, name="test"
        )
        call_count = 0

        @breaker
        def flaky() -> str:
            nonlocal call_count
            call_count += 1
            if call_count in (1, 2):
                raise RuntimeError("fail")
            return "ok"

        with pytest.raises(RuntimeError):
            flaky()
        with pytest.raises(RuntimeError):
            flaky()
        # 2 failures, threshold is 3 — one success resets counter
        assert flaky() == "ok"

        # Now fail again — counter should be reset to 0
        call_count = 0  # Reset our counter
        with pytest.raises(RuntimeError):
            flaky()
        with pytest.raises(RuntimeError):
            flaky()
        # Still not open because count was reset
        assert flaky() == "ok"
