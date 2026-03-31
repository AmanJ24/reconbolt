"""Event system for real-time scan progress reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


class ScanPhase(str, Enum):
    """Phases of a reconnaissance scan."""

    INITIALIZING = "initializing"
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    PORT_SCAN = "port_scanning"
    VULN_SCAN = "vulnerability_scanning"
    OSINT = "osint_gathering"
    TAKEOVER_CHECK = "takeover_check"
    AI_ANALYSIS = "ai_analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"


class EventLevel(str, Enum):
    """Severity/type of a scan event."""

    DEBUG = "debug"
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    COMMAND = "command"


@dataclass
class ScanEvent:
    """A single event emitted during a scan."""

    phase: ScanPhase
    level: EventLevel
    message: str
    progress: float = 0.0  # 0.0 - 100.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for WebSocket / JSON transport."""
        return {
            "phase": self.phase.value,
            "level": self.level.value,
            "message": self.message,
            "progress": round(self.progress, 1),
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


# Type alias for event callback functions
EventCallback = Callable[[ScanEvent], None]


class EventEmitter:
    """Manages event listeners and dispatching for scan progress."""

    def __init__(self) -> None:
        self._listeners: list[EventCallback] = []

    def on_event(self, callback: EventCallback) -> None:
        """Register an event listener."""
        self._listeners.append(callback)

    def emit(self, event: ScanEvent) -> None:
        """Dispatch an event to all registered listeners."""
        for listener in self._listeners:
            try:
                listener(event)
            except Exception:
                pass  # Don't let a listener failure break the scan

    def log(self, phase: ScanPhase, level: EventLevel, message: str, progress: float = 0.0, **data: Any) -> None:
        """Convenience method to create and emit an event."""
        event = ScanEvent(
            phase=phase,
            level=level,
            message=message,
            progress=progress,
            data=data if data else None,
        )
        self.emit(event)

    def info(self, phase: ScanPhase, message: str, progress: float = 0.0) -> None:
        self.log(phase, EventLevel.INFO, message, progress)

    def success(self, phase: ScanPhase, message: str, progress: float = 0.0) -> None:
        self.log(phase, EventLevel.SUCCESS, message, progress)

    def warning(self, phase: ScanPhase, message: str, progress: float = 0.0) -> None:
        self.log(phase, EventLevel.WARNING, message, progress)

    def error(self, phase: ScanPhase, message: str, progress: float = 0.0) -> None:
        self.log(phase, EventLevel.ERROR, message, progress)

    def command(self, phase: ScanPhase, message: str, progress: float = 0.0) -> None:
        self.log(phase, EventLevel.COMMAND, message, progress)
