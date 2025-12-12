"""Main entry point for the Security Scanner application."""

import logging
import sys

import uvicorn

from src.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)

# Reduce noise from third-party loggers
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def main():
    """Run the application."""
    logger.info("Starting Security Scanner")
    logger.info("Target: %s", settings.target_host)
    logger.info("Scan interval: %d hours", settings.scan_interval_hours)
    logger.info("SMTP configured: %s", settings.smtp_configured)
    logger.info("Webhook configured: %s", settings.webhook_configured)

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
