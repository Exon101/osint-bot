"""
Unit tests for the OSINT Bot config module.
"""

import os
import pytest
from config import Config, config


class TestConfigDefaults:
    """Test default configuration values."""

    def test_has_telegram_token_field(self):
        assert hasattr(config, "TELEGRAM_BOT_TOKEN")

    def test_has_api_key_fields(self):
        expected_keys = [
            "IPINFO_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "SHODAN_API_KEY",
            "HUNTER_API_KEY",
            "ABUSEIPDB_API_KEY",
            "GITHUB_TOKEN",
        ]
        for key in expected_keys:
            assert hasattr(config, key), f"Missing config field: {key}"

    def test_has_rate_limit_settings(self):
        assert hasattr(config, "RATE_LIMIT")
        assert hasattr(config, "RATE_WINDOW")
        assert isinstance(config.RATE_LIMIT, int)
        assert isinstance(config.RATE_WINDOW, int)

    def test_rate_limit_positive(self):
        assert config.RATE_LIMIT > 0
        assert config.RATE_WINDOW > 0

    def test_has_feature_flags(self):
        assert hasattr(config, "ENABLE_LOGGING")
        assert hasattr(config, "ENABLE_CODE_RUNNER")
        assert hasattr(config, "ENABLE_PASSWORD_GEN")

    def test_has_database_url(self):
        assert hasattr(config, "DATABASE_URL")

    def test_admin_ids_is_list(self):
        assert isinstance(config.ADMIN_IDS, list)

    def test_code_runner_settings(self):
        assert hasattr(config, "CODE_RUNNER_TIMEOUT")
        assert hasattr(config, "CODE_RUNNER_MAX_OUTPUT")
        assert config.CODE_RUNNER_TIMEOUT > 0
        assert config.CODE_RUNNER_MAX_OUTPUT > 0


class TestConfigFromEnv:
    """Test configuration from environment variables."""

    def test_reads_telegram_token_from_env(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_TOKEN", "test_token_123")
        cfg = Config()
        assert cfg.TELEGRAM_BOT_TOKEN == "test_token_123"

    def test_reads_ipinfo_key_from_env(self, monkeypatch):
        monkeypatch.setenv("IPINFO_API_KEY", "test_ipinfo")
        cfg = Config()
        assert cfg.IPINFO_API_KEY == "test_ipinfo"

    def test_reads_virustotal_key_from_env(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_vt")
        cfg = Config()
        assert cfg.VIRUSTOTAL_API_KEY == "test_vt"

    def test_env_overrides_default(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_TOKEN", "env_token")
        cfg = Config()
        assert cfg.TELEGRAM_BOT_TOKEN == "env_token"

    def test_custom_rate_limit(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_TOKEN", "test")
        cfg = Config()
        assert cfg.RATE_LIMIT == 10
        assert cfg.RATE_WINDOW == 60


class TestConfigSingleton:
    """Test that config is a singleton instance."""

    def test_config_is_config_instance(self):
        assert isinstance(config, Config)

    def test_config_has_telegram_token(self):
        assert isinstance(config.TELEGRAM_BOT_TOKEN, str)
