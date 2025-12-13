"""Main entry point for the Security Scanner application."""

import logging
import sys
from datetime import datetime

import uvicorn

from src.config import settings


def configure_logging():
    """Configure logging based on settings."""
    log_level = getattr(logging, settings.log_level.upper())

    if settings.log_format == "json":
        from pythonjsonlogger import jsonlogger

        class CustomJsonFormatter(jsonlogger.JsonFormatter):
            """Custom JSON formatter with additional fields."""

            def add_fields(self, log_record, record, message_dict):
                super().add_fields(log_record, record, message_dict)
                log_record["timestamp"] = datetime.utcnow().isoformat() + "Z"
                log_record["level"] = record.levelname
                log_record["logger"] = record.name
                log_record["service"] = "ld-host-scanner"

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(CustomJsonFormatter(
            "%(timestamp)s %(level)s %(name)s %(message)s"
        ))
        logging.root.handlers = []
        logging.root.addHandler(handler)
        logging.root.setLevel(log_level)
    else:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout),
            ],
        )


# Configure logging
configure_logging()

# Reduce noise from third-party loggers
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def main():
    """Run the application."""
    from src.version import __version__

    logger.info("Starting LD Host Scanner v%s", __version__)
    logger.info("Target: %s", settings.target_host)
    logger.info("Scan interval: %d hours", settings.scan_interval_hours)
    logger.info("SMTP configured: %s", settings.smtp_configured)
    logger.info("Webhook configured: %s", settings.webhook_configured)
    logger.info("Expected ports configured: %s", settings.expected_ports_configured)
    if settings.expected_ports_configured:
        logger.info("Expected ports: %s", settings.expected_ports)
    logger.info("Log format: %s", settings.log_format)

    # Import app here to ensure logging is configured first
    from src.web.app import app

    uvicorn.run(
        app,
        host=settings.web_host,
        port=settings.web_port,
        log_level=settings.log_level.lower(),
    )


# Export app for uvicorn command line usage
from src.web.app import app  # noqa: E402

if __name__ == "__main__":
    main()
