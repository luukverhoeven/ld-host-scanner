"""Tests for version module."""

import os
from unittest.mock import patch


class TestVersionModule:
    """Tests for version information."""

    def test_version_string_format(self):
        """Test version string is valid semver format."""
        from src.version import __version__

        parts = __version__.split(".")
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)

    def test_version_info_tuple(self):
        """Test version info tuple matches version string."""
        from src.version import __version__, __version_info__

        assert len(__version_info__) == 3
        expected = ".".join(str(v) for v in __version_info__)
        assert __version__ == expected

    def test_get_version_returns_string(self):
        """Test get_version() returns the version string."""
        from src.version import get_version, __version__

        assert get_version() == __version__

    def test_get_version_info_returns_dict(self):
        """Test get_version_info() returns dict with expected keys."""
        from src.version import get_version_info, __version__

        info = get_version_info()

        assert isinstance(info, dict)
        assert "version" in info
        assert "build_date" in info
        assert "git_commit" in info
        assert info["version"] == __version__

    def test_build_info_from_environment(self):
        """Test build info reads from environment variables."""
        with patch.dict(os.environ, {
            "APP_BUILD_DATE": "2025-01-01T00:00:00Z",
            "APP_GIT_COMMIT": "abc1234",
        }):
            # Need to reimport to pick up env vars
            import importlib
            import src.version
            importlib.reload(src.version)

            info = src.version.get_version_info()
            assert info["build_date"] == "2025-01-01T00:00:00Z"
            assert info["git_commit"] == "abc1234"

            # Reload again to reset
            importlib.reload(src.version)

    def test_build_info_none_when_not_set(self):
        """Test build info is None when env vars not set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove the env vars if they exist
            os.environ.pop("APP_BUILD_DATE", None)
            os.environ.pop("APP_GIT_COMMIT", None)

            import importlib
            import src.version
            importlib.reload(src.version)

            info = src.version.get_version_info()
            assert info["build_date"] is None
            assert info["git_commit"] is None

            # Reload again to reset
            importlib.reload(src.version)
