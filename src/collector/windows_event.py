import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from src.collector.base import BaseCollector, CollectEvent

logger = logging.getLogger(__name__)


class WindowsEventCollector(BaseCollector):
    SIMULATED_EVENTS: ClassVar[list[dict]] = [
        {
            "EventId": 4625,
            "EventLog": "Security",
            "EventType": "AUDIT_FAILURE",
            "Computer": "WIN-SRV-01",
            "TimeCreated": None,
            "EventData": {
                "TargetUserName": "Administrator",
                "TargetDomainName": "WORKGROUP",
                "WorkstationName": "WIN-SRV-01",
                "LogonType": "3",
                "IpAddress": "192.168.1.100",
                "IpPort": "54321",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
            },
        },
        {
            "EventId": 4688,
            "EventLog": "Security",
            "EventType": "AUDIT_SUCCESS",
            "Computer": "WIN-SRV-01",
            "TimeCreated": None,
            "EventData": {
                "SubjectUserName": "SYSTEM",
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CreatorProcessName": "C:\\Windows\\System32\\svchost.exe",
                "ProcessId": "4520",
                "CommandLine": "C:\\Windows\\System32\\cmd.exe /c net user hacker Password123! /add",
            },
        },
        {
            "EventId": 7045,
            "EventLog": "System",
            "EventType": "INFO",
            "Computer": "WIN-SRV-01",
            "TimeCreated": None,
            "EventData": {
                "ServiceName": "RemoteAccessSvc",
                "ImagePath": "C:\\Users\\Public\\svchost.exe -n",
                "ServiceType": "user_mode_service",
                "StartType": "auto_start",
            },
        },
        {
            "EventId": 1,
            "EventLog": "Microsoft-Windows-Sysmon/Operational",
            "EventType": "INFO",
            "Computer": "WIN-SRV-01",
            "TimeCreated": None,
            "EventData": {
                "ProcessGuid": "{A23E4D52-1234-5678-9012-345678901234}",
                "ProcessId": "6789",
                "Image": "C:\\Users\\Public\\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFIARQApAA==",
                "CurrentDirectory": "C:\\Users\\Public\\",
                "User": "WIN-SRV-01\\Administrator",
                "ParentImage": "C:\\Program Files\\Internet Explorer\\iexplore.exe",
                "ParentCommandLine": "iexplore.exe http://malicious.example.com/exploit",
            },
        },
    ]

    def __init__(self, config: dict | None = None):
        super().__init__("windows_event", config)
        self.simulation_mode = self.config.get("simulation_mode", True)
        self.simulation_interval = self.config.get("simulation_interval", 5)
        self.simulation_file = self.config.get("simulation_file")
        self._task: asyncio.Task | None = None

    async def start(self):
        self._running = True
        if self.simulation_mode:
            self._task = asyncio.create_task(self._simulate_events())
            logger.info(
                f"Windows Event collector started in simulation mode "
                f"(interval={self.simulation_interval}s)"
            )
        else:
            logger.info("Windows Event collector started (live mode - Windows only)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Windows Event collector stopped")

    async def collect(self) -> CollectEvent | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=1.0)
        except TimeoutError:
            return None

    def ingest_event(self, raw_data: dict) -> CollectEvent | None:
        try:
            event_id = raw_data.get("EventId", raw_data.get("EventID", 0))
            event_log = raw_data.get("EventLog", raw_data.get("LogName", "Unknown"))
            event_type = raw_data.get("EventType", "INFO")
            computer = raw_data.get("Computer", raw_data.get("ComputerName", "unknown"))
            event_data = raw_data.get("EventData", raw_data)

            raw_ts = raw_data.get("TimeCreated")
            if isinstance(raw_ts, str):
                try:
                    ts = datetime.fromisoformat(raw_ts)
                except ValueError:
                    ts = datetime.now(UTC)
            else:
                ts = datetime.now(UTC)

            event = CollectEvent(
                source=f"windows/{event_log}",
                event_type=f"windows_event_{event_id}",
                data={
                    "event_id": event_id,
                    "event_log": event_log,
                    "event_type": event_type,
                    "computer": computer,
                    "event_data": event_data,
                },
                timestamp=ts,
                host=computer,
            )
            self.on_event(event)
            return event
        except Exception:
            logger.exception("Failed to ingest Windows event")
            return None

    async def _simulate_events(self):
        try:
            idx = 0
            while self._running:
                template = self.SIMULATED_EVENTS[idx % len(self.SIMULATED_EVENTS)]
                event_data = dict(template)
                event_data["TimeCreated"] = datetime.now(UTC).isoformat()

                event = CollectEvent(
                    source=f"windows/{event_data['EventLog']}",
                    event_type=f"windows_event_{event_data['EventId']}",
                    data=event_data,
                    host=event_data["Computer"],
                )
                self._enqueue(event)
                await self.emit(event)
                idx += 1
                await asyncio.sleep(self.simulation_interval)

                if self.simulation_file:
                    try:
                        path = Path(self.simulation_file)
                        if path.exists():
                            content = path.read_text(encoding="utf-8")
                            for line in content.splitlines():
                                line = line.strip()
                                if line:
                                    try:
                                        parsed = json.loads(line)
                                        self.ingest_event(parsed)
                                    except json.JSONDecodeError:
                                        logger.warning(f"Invalid JSON in simulation file: {line}")
                    except Exception:
                        logger.exception("Error reading simulation file")
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Simulation loop crashed")
