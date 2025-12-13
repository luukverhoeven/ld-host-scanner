"""Version information for LD Host Scanner."""

import os

__version__ = "1.1.0"
__version_info__ = (1, 1, 0)

# Build info from environment (set by Docker build args)
BUILD_DATE = os.getenv("APP_BUILD_DATE")
GIT_COMMIT = os.getenv("APP_GIT_COMMIT")


def get_version() -> str:
    """Get the current version string."""
    return __version__


def get_version_info() -> dict:
    """Get detailed version information."""
    return {
        "version": __version__,
        "build_date": BUILD_DATE,
        "git_commit": GIT_COMMIT,
    }
