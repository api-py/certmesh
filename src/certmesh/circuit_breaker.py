"""
certmesh.circuit_breaker
=========================

A lightweight, thread-safe circuit breaker implemented as a factory function
returning a callable decorator.

State machine::

    CLOSED ──(failures >= threshold)──> OPEN
      ^                                    |
      |                           (recovery_timeout elapsed)
      |                                    v
      └──────────(probe succeeds)──── HALF_OPEN
                                           |
                                  (probe fails)
                                           |
                                           v
                                         OPEN
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from enum import Enum
from typing import Any, TypeVar

from certmesh.exceptions import CircuitBreakerOpenError

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class _State(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


def create_circuit_breaker(
    *,
    failure_threshold: int,
    recovery_timeout_seconds: float,
    name: str = "unnamed",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Return a decorator that wraps callables with circuit breaker protection."""
    if failure_threshold < 1:
        raise ValueError("failure_threshold must be >= 1.")
    if recovery_timeout_seconds <= 0:
        raise ValueError("recovery_timeout_seconds must be > 0.")

    _state: dict[str, Any] = {
        "circuit": _State.CLOSED,
        "failure_count": 0,
        "last_failure_time": None,
    }
    _lock = threading.Lock()

    def _on_success() -> None:
        if _state["circuit"] != _State.CLOSED:
            logger.info(
                "Circuit breaker '%s': probe succeeded — transitioning %s -> CLOSED.",
                name,
                _state["circuit"].value,
            )
        _state["circuit"] = _State.CLOSED
        _state["failure_count"] = 0

    def _on_failure() -> None:
        _state["failure_count"] += 1
        _state["last_failure_time"] = time.monotonic()

        if _state["failure_count"] >= failure_threshold:
            previous = _state["circuit"]
            _state["circuit"] = _State.OPEN
            if previous != _State.OPEN:
                logger.warning(
                    "Circuit breaker '%s': opened after %d consecutive failures.",
                    name,
                    _state["failure_count"],
                )
        else:
            logger.debug(
                "Circuit breaker '%s': failure %d/%d recorded.",
                name,
                _state["failure_count"],
                failure_threshold,
            )

    def _check_and_maybe_advance() -> None:
        circuit = _state["circuit"]
        if circuit == _State.OPEN:
            elapsed: float = time.monotonic() - _state["last_failure_time"]
            remaining: float = recovery_timeout_seconds - elapsed
            if elapsed >= recovery_timeout_seconds:
                _state["circuit"] = _State.HALF_OPEN
                logger.info(
                    "Circuit breaker '%s': recovery timeout elapsed — "
                    "transitioning OPEN -> HALF_OPEN.",
                    name,
                )
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{name}' is OPEN. Next probe allowed in {remaining:.1f}s."
                )
        elif circuit == _State.HALF_OPEN:
            logger.debug("Circuit breaker '%s': allowing HALF_OPEN probe call.", name)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with _lock:
                _check_and_maybe_advance()

            try:
                result = func(*args, **kwargs)
            except CircuitBreakerOpenError:
                raise
            except Exception as exc:
                with _lock:
                    _on_failure()
                logger.debug(
                    "Circuit breaker '%s': recorded failure — %s: %s",
                    name,
                    type(exc).__name__,
                    exc,
                )
                raise
            else:
                with _lock:
                    _on_success()
                return result

        wrapper.__name__ = getattr(func, "__name__", "wrapped")
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator
