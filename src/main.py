import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import uvicorn

from src.collector.syslog import SyslogCollector
from src.collector.windows_event import WindowsEventCollector
from src.engine.correlator import CorrelationEngine
from src.engine.rules import RuleEngine
from src.storage.database import get_db

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class SentinelEye:
    def __init__(self, rules_dir: str | None = None, db_url: str | None = None):
        self.rules_dir = rules_dir or os.getenv(
            "SENTINEL_RULES_DIR",
            str(Path(__file__).parent.parent / "examples" / "rules"),
        )
        self.db_url = db_url or os.getenv("SENTINEL_DB_URL")

        self.db = get_db()
        self.rule_engine = RuleEngine(rules_dir=self.rules_dir)
        self.correlation_engine = CorrelationEngine(
            alert_manager=self.rule_engine.alert_manager
        )
        self.collectors: list = []
        self._running = False

        self._setup_default_correlation_rules()

    def _setup_default_correlation_rules(self):
        for rule in [
            CorrelationEngine.brute_force_detection_rule(),
            CorrelationEngine.port_scan_detection_rule(),
            CorrelationEngine.beaconing_detection_rule(),
        ]:
            self.correlation_engine.add_rule(rule)

    async def _handle_event(self, event):
        try:
            event_id = self.db.insert_event(event.to_dict())
            event.id = event_id

            alert = self.rule_engine.process_event(event)
            if alert:
                self.db.insert_alert(alert.to_dict())

            corr_alert = self.correlation_engine.process_event(event)
            if corr_alert:
                self.db.insert_alert(corr_alert.to_dict())

        except Exception:
            logger.exception("Failed to process event")

    async def _handle_alert(self, alert):
        try:
            self.db.insert_alert(alert.to_dict())
        except Exception:
            logger.exception("Failed to persist alert")

    async def start(self):
        self._running = True

        syslog = SyslogCollector()
        syslog.add_hook(self._handle_event)
        self.collectors.append(syslog)

        win_evt = WindowsEventCollector()
        win_evt.add_hook(self._handle_event)
        self.collectors.append(win_evt)

        for collector in self.collectors:
            await collector.start()

        logger.info(
            f"SentinelEye started with {len(self.rule_engine.rules)} rules, "
            f"{len(self.correlation_engine.rules)} correlation rules"
        )

        while self._running:
            await asyncio.sleep(1)

    async def stop(self):
        self._running = False
        for collector in self.collectors:
            await collector.stop()
        logger.info("SentinelEye stopped")


def run_api(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    from src.api.server import create_app
    app = create_app()
    logger.info(f"Starting API server on {host}:{port}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


async def run_agent(rules_dir: str | None = None, db_url: str | None = None):
    sentinel = SentinelEye(rules_dir=rules_dir, db_url=db_url)

    def shutdown_handler():
        asyncio.create_task(sentinel.stop())

    try:
        if sys.platform != "win32":
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, shutdown_handler)
    except NotImplementedError:
        pass

    try:
        await sentinel.start()
    except KeyboardInterrupt:
        await sentinel.stop()


def main():
    parser = argparse.ArgumentParser(
        description="SentinelEye - SIEM/HIDS System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["api", "agent", "all"],
        default=os.getenv("SENTINEL_MODE", "all"),
        help="Run mode (api, agent, or all)",
    )
    parser.add_argument("--host", default=os.getenv("SENTINEL_HOST", "0.0.0.0"), help="API host")
    parser.add_argument("--port", type=int, default=int(os.getenv("SENTINEL_PORT", "8000")), help="API port")
    parser.add_argument("--rules-dir", default=os.getenv("SENTINEL_RULES_DIR"), help="Rules directory")
    parser.add_argument("--db-url", default=os.getenv("SENTINEL_DB_URL"), help="Database URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--reload", action="store_true", help="Auto-reload API (development)")

    args = parser.parse_args()
    setup_logging(args.verbose)

    mode = args.mode

    if mode == "api":
        run_api(host=args.host, port=args.port, reload=args.reload)
    elif mode == "agent":
        asyncio.run(run_agent(rules_dir=args.rules_dir, db_url=args.db_url))
    elif mode == "all":
        import threading
        api_thread = threading.Thread(
            target=run_api,
            args=(args.host, args.port, args.reload),
            daemon=True,
        )
        api_thread.start()
        asyncio.run(run_agent(rules_dir=args.rules_dir, db_url=args.db_url))


if __name__ == "__main__":
    main()
