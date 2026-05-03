#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for file input validation
"""

from src.core.input_validator import FileValidator


class TestFileValidator:
    """Test cases for FileValidator."""

    def test_validate_file_path_rejects_sibling_directory_prefix(self, monkeypatch, tmp_path):
        """Sibling paths with a shared string prefix should not pass containment."""
        workspace = tmp_path / "repo"
        sibling = tmp_path / "repo_evil"
        workspace.mkdir()
        sibling.mkdir()
        outside_file = sibling / "sample.py"
        outside_file.write_text("print('outside')\n")
        monkeypatch.chdir(workspace)

        result = FileValidator().validate_file_path(outside_file)

        assert result.is_valid is False
        assert result.risk_level == "critical"
