import asyncio
import logging
import re
from datetime import UTC, datetime

from src.collector.base import BaseCollector, CollectEvent

logger = logging.getLogger(__name__)

RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<tag>[^:]+):?\s*(?P<content>.*)$"
)

PRIORITY_FACILITY = 0
PRIORITY_SEVERITY = 1

SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

FACILITY_MAP = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}


def parse_rfc3164(message: str) -> dict | None:
    match = RFC3164_PATTERN.match(message.strip())
    if not match:
        return None

    pri = int(match.group("pri"))
    facility = (pri >> 3) & 0x1F
    severity = pri & 0x07

    raw_ts = match.group("timestamp")
    host = match.group("host")
    tag = match.group("tag")
    content = match.group("content")

    try:
        # RFC 3164 timestamps carry no year: parse with the current one so
        # Feb 29 works and Python 3.15+ does not reject the format.
        year = datetime.now(UTC).year
        parsed_ts = datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
        parsed_ts = parsed_ts.replace(tzinfo=UTC)
    except ValueError:
        parsed_ts = datetime.now(UTC)

    return {
        "priority": pri,
        "facility": FACILITY_MAP.get(facility, f"unknown({facility})"),
        "facility_code": facility,
        "severity": SEVERITY_MAP.get(severity, f"unknown({severity})"),
        "severity_code": severity,
        "timestamp": parsed_ts.isoformat(),
        "hostname": host,
        "tag": tag,
        "message": content,
    }


class SyslogCollector(BaseCollector):
    def __init__(self, config: dict | None = None):
        super().__init__("syslog", config)
        self.udp_host = self.config.get("udp_host", "0.0.0.0")
        self.udp_port = self.config.get("udp_port", 514)
        self.tcp_host = self.config.get("tcp_host", "0.0.0.0")
        self.tcp_port = self.config.get("tcp_port", 5140)
        self._udp_server: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None

    async def start(self):
        self._running = True

        try:
            loop = asyncio.get_event_loop()
            self._udp_server, _ = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self),
                local_addr=(self.udp_host, self.udp_port),
            )
            logger.info(f"Syslog UDP collector listening on {self.udp_host}:{self.udp_port}")
        except OSError as e:
            logger.warning(f"Could not start UDP syslog listener: {e}")

        try:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                self.tcp_host,
                self.tcp_port,
            )
            logger.info(f"Syslog TCP collector listening on {self.tcp_host}:{self.tcp_port}")
        except OSError as e:
            logger.warning(f"Could not start TCP syslog listener: {e}")


    async def stop(self):
        self._running = False
        if self._udp_server:
            self._udp_server.close()
        if self._tcp_server:
            self._tcp_server.close()
        logger.info("Syslog collector stopped")

    async def collect(self) -> CollectEvent | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=1.0)
        except TimeoutError:
            return None

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        logger.debug(f"TCP connection from {addr}")
        try:
            while self._running:
                data = await reader.readline()
                if not data:
                    break
                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    await self._parse_and_enqueue(message, "tcp", str(addr))
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception(f"Error handling TCP client {addr}")
        finally:
            writer.close()
            await writer.wait_closed()

    def _handle_udp_datagram(self, data: bytes, addr: tuple):
        try:
            message = data.decode("utf-8", errors="replace").strip()
            if message:
                asyncio.create_task(self._parse_and_enqueue(message, "udp", str(addr)))
        except Exception:
            logger.exception("Error handling UDP datagram")

    async def _parse_and_enqueue(self, message: str, protocol: str, addr: str):
        parsed = parse_rfc3164(message)
        if parsed:
            event = CollectEvent(
                source=f"syslog/{protocol}",
                event_type="syslog",
                data=parsed,
                host=parsed.get("hostname", addr),
            )
            self._enqueue(event)
            await self.emit(event)


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector):
        self.collector = collector

    def datagram_received(self, data: bytes, addr):
        self.collector._handle_udp_datagram(data, addr)
