import asyncio

import pytest

from src.collector.base import CollectEvent
from src.collector.syslog import SyslogCollector, parse_rfc3164
from src.collector.windows_event import WindowsEventCollector


class TestCollectEvent:
    def test_to_dict(self):
        event = CollectEvent(
            source="test",
            event_type="test_event",
            data={"key": "value"},
            host="testhost",
        )
        d = event.to_dict()
        assert d["source"] == "test"
        assert d["event_type"] == "test_event"
        assert d["data"] == {"key": "value"}
        assert d["host"] == "testhost"
        assert "timestamp" in d

    def test_round_trip(self):
        event = CollectEvent(
            source="test",
            event_type="test_event",
            data={"nested": {"a": 1}},
            host="host1",
        )
        d = event.to_dict()
        restored = CollectEvent.from_dict(d)
        assert restored.source == event.source
        assert restored.event_type == event.event_type
        assert restored.data == event.data
        assert restored.host == event.host


class TestParseRFC3164:
    def test_valid_syslog(self):
        msg = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        parsed = parse_rfc3164(msg)
        assert parsed is not None
        assert parsed["priority"] == 34
        assert parsed["facility"] == "auth"
        assert parsed["severity"] == "critical"
        assert parsed["hostname"] == "mymachine"
        assert parsed["tag"] == "su"
        assert "failed" in parsed["message"]

    def test_ssh_message(self):
        msg = "<38>Jan  3 12:34:56 ssh-server sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
        parsed = parse_rfc3164(msg)
        assert parsed is not None
        assert parsed["hostname"] == "ssh-server"
        assert parsed["tag"] == "sshd[1234]"
        assert "Failed password" in parsed["message"]

    def test_invalid_message(self):
        assert parse_rfc3164("") is None
        assert parse_rfc3164("garbage data here") is None

    def test_local_emergency(self):
        msg = "<0>Mar 15 08:30:00 kernel Kernel panic - not syncing: Fatal exception"
        parsed = parse_rfc3164(msg)
        assert parsed is not None
        assert parsed["facility"] == "kern"
        assert parsed["severity"] == "emergency"


class TestSyslogCollector:
    @pytest.mark.asyncio
    async def test_start_stop(self):
        collector = SyslogCollector({"udp_port": 0, "tcp_port": 0})
        await collector.start()
        assert collector.is_running
        await collector.stop()
        assert not collector.is_running

    @pytest.mark.asyncio
    async def test_parse_and_enqueue(self):
        collector = SyslogCollector()
        collector._running = True
        events = []

        async def hook(event):
            events.append(event)

        collector.add_hook(hook)

        msg = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed"
        await collector._parse_and_enqueue(msg, "test", "127.0.0.1")

        assert len(events) == 1
        assert events[0].source == "syslog/test"
        assert events[0].data["hostname"] == "mymachine"


class TestWindowsEventCollector:
    @pytest.mark.asyncio
    async def test_start_stop_simulation(self):
        collector = WindowsEventCollector({"simulation_interval": 1})
        await collector.start()
        assert collector.is_running
        await asyncio.sleep(0.1)
        await collector.stop()
        assert not collector.is_running

    def test_ingest_event(self):
        collector = WindowsEventCollector()
        raw = {
            "EventId": 4625,
            "EventLog": "Security",
            "EventType": "AUDIT_FAILURE",
            "Computer": "WIN-PC",
            "TimeCreated": "2026-06-29T10:00:00+00:00",
            "EventData": {"TargetUserName": "admin", "Status": "0xC000006D"},
        }
        event = collector.ingest_event(raw)
        assert event is not None
        assert event.source == "windows/Security"
        assert event.event_type == "windows_event_4625"
        assert event.host == "WIN-PC"
        assert event.data["event_data"]["TargetUserName"] == "admin"

    def test_ingest_invalid_event(self):
        collector = WindowsEventCollector()
        event = collector.ingest_event({})
        assert event is not None

    @pytest.mark.asyncio
    async def test_simulation_produces_events(self):
        collector = WindowsEventCollector({"simulation_interval": 0.1})
        events = []

        async def hook(event):
            events.append(event)

        collector.add_hook(hook)
        await collector.start()
        await asyncio.sleep(0.35)
        await collector.stop()

        assert len(events) >= 2
        for event in events:
            assert event.source.startswith("windows/")
            assert event.event_type.startswith("windows_event_")
