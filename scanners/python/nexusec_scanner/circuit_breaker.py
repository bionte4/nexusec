"""Per-target circuit breaker for the custom scanner."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """
    Opens after ``failure_threshold`` consecutive failures for a target.

    While OPEN, probes are skipped until ``recovery_timeout`` elapses, then
    ONE trial probe is allowed (HALF_OPEN). Success closes the circuit.
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    _failures: dict[str, int] = field(default_factory=dict)
    _opened_at: dict[str, float] = field(default_factory=dict)
    _state: dict[str, CircuitState] = field(default_factory=dict)

    def state(self, target: str) -> CircuitState:
        current = self._state.get(target, CircuitState.CLOSED)
        if current == CircuitState.OPEN:
            opened = self._opened_at.get(target, 0.0)
            if time.monotonic() - opened >= self.recovery_timeout:
                self._state[target] = CircuitState.HALF_OPEN
                return CircuitState.HALF_OPEN
        return current

    def allow(self, target: str) -> bool:
        st = self.state(target)
        return st in {CircuitState.CLOSED, CircuitState.HALF_OPEN}

    def record_success(self, target: str) -> None:
        self._failures[target] = 0
        self._state[target] = CircuitState.CLOSED
        self._opened_at.pop(target, None)

    def record_failure(self, target: str) -> None:
        st = self.state(target)
        if st == CircuitState.HALF_OPEN:
            self._trip(target)
            return
        count = self._failures.get(target, 0) + 1
        self._failures[target] = count
        if count >= self.failure_threshold:
            self._trip(target)

    def _trip(self, target: str) -> None:
        self._state[target] = CircuitState.OPEN
        self._opened_at[target] = time.monotonic()
