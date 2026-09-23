"""Tests for wlanpi_mcp configuration defaults."""

import ssl

from wlanpi_mcp.client.tls import core_ssl_context
from wlanpi_mcp.config import CLASSROOM_TOOLS, Settings


def test_loopback_only_bind_default() -> None:
    """The daemon must stay loopback-only so only nginx fronts the public ports."""
    assert Settings(_env_file=None).WLANPI_MCP_HOST == "127.0.0.1"


def test_tool_profile_defaults_to_every_tool() -> None:
    assert Settings(_env_file=None).enabled_tools() is None


def test_classroom_profile_selects_classroom_tools() -> None:
    settings = Settings(TOOL_PROFILE="classroom", _env_file=None)
    assert settings.enabled_tools() == CLASSROOM_TOOLS


def test_explicit_allowlist_overrides_profile() -> None:
    settings = Settings(
        TOOL_PROFILE="classroom",
        TOOL_ALLOWLIST=" get_device_info, scan_wlan ,,",
        _env_file=None,
    )
    assert settings.enabled_tools() == {"get_device_info", "scan_wlan"}


def test_token_in_config_file_is_ignored(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("WLANPI_CORE_TOKEN", raising=False)
    env_file = tmp_path / "config.env"
    env_file.write_text("WLANPI_CORE_TOKEN=from-file\nLOG_LEVEL=DEBUG\n")
    settings = Settings(_env_file=env_file)
    assert settings.WLANPI_CORE_TOKEN == ""
    # The rest of the file still loads.
    assert settings.LOG_LEVEL == "DEBUG"


def test_token_from_environment_is_used(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WLANPI_CORE_TOKEN", "from-env")
    env_file = tmp_path / "config.env"
    env_file.write_text("WLANPI_CORE_TOKEN=from-file\n")
    assert Settings(_env_file=env_file).WLANPI_CORE_TOKEN == "from-env"


def test_missing_ca_falls_back_to_verifying_system_store(tmp_path, caplog) -> None:
    settings = Settings(WLANPI_CORE_CA=str(tmp_path / "absent.cert"), _env_file=None)
    ctx = core_ssl_context(settings)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname
    assert "not found" in caplog.text
