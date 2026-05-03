#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for configuration managers
"""

from src.infrastructure.config_manager import JsonConfigManager


class TestJsonConfigManager:
    """Test cases for JsonConfigManager."""

    def test_load_env_config_ignores_invalid_integer_values(self, monkeypatch, tmp_path):
        """Invalid integer environment values should not discard config loading."""
        monkeypatch.setenv("REQUEST_TIMEOUT", "not-a-number")
        monkeypatch.setenv("MAX_RETRIES", "4")
        manager = JsonConfigManager(config_dir=str(tmp_path))

        env_config = manager._load_env_config()

        assert env_config["analyzer"]["max_retries"] == 4
        assert "api_timeout" not in env_config["analyzer"]
