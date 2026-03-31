"""Tests for the event system."""

from reconbolt.engine.events import EventEmitter, EventLevel, ScanEvent, ScanPhase


class TestEventEmitter:
    """Tests for the event emitter."""

    def test_emit_event(self):
        emitter = EventEmitter()
        received = []
        emitter.on_event(lambda e: received.append(e))

        emitter.info(ScanPhase.INITIALIZING, "test message", progress=50.0)

        assert len(received) == 1
        assert received[0].message == "test message"
        assert received[0].phase == ScanPhase.INITIALIZING
        assert received[0].level == EventLevel.INFO
        assert received[0].progress == 50.0

    def test_multiple_listeners(self):
        emitter = EventEmitter()
        received_a = []
        received_b = []
        emitter.on_event(lambda e: received_a.append(e))
        emitter.on_event(lambda e: received_b.append(e))

        emitter.success(ScanPhase.COMPLETED, "done")

        assert len(received_a) == 1
        assert len(received_b) == 1

    def test_listener_error_doesnt_break(self):
        emitter = EventEmitter()
        emitter.on_event(lambda e: 1 / 0)  # Will raise ZeroDivisionError
        received = []
        emitter.on_event(lambda e: received.append(e))

        emitter.info(ScanPhase.PORT_SCAN, "should still work")
        assert len(received) == 1

    def test_event_serialization(self):
        event = ScanEvent(
            phase=ScanPhase.SUBDOMAIN_ENUM,
            level=EventLevel.WARNING,
            message="test",
            progress=75.5,
        )
        data = event.to_dict()
        assert data["phase"] == "subdomain_enumeration"
        assert data["level"] == "warning"
        assert data["progress"] == 75.5
        assert "timestamp" in data

    def test_convenience_methods(self):
        emitter = EventEmitter()
        events = []
        emitter.on_event(lambda e: events.append(e))

        emitter.info(ScanPhase.PORT_SCAN, "info")
        emitter.success(ScanPhase.PORT_SCAN, "success")
        emitter.warning(ScanPhase.PORT_SCAN, "warning")
        emitter.error(ScanPhase.PORT_SCAN, "error")
        emitter.command(ScanPhase.PORT_SCAN, "$ nmap")

        assert len(events) == 5
        assert events[0].level == EventLevel.INFO
        assert events[1].level == EventLevel.SUCCESS
        assert events[2].level == EventLevel.WARNING
        assert events[3].level == EventLevel.ERROR
        assert events[4].level == EventLevel.COMMAND
