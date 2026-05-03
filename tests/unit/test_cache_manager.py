#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for cache managers
"""

from src.core.interfaces import AnalysisResult
from src.infrastructure.cache_manager import FileCacheManager


class TestFileCacheManager:
    """Test cases for FileCacheManager."""

    def test_rejects_invalid_hash_path_components(self, tmp_path):
        """Invalid cache keys should not be used as filesystem paths."""
        cache_dir = tmp_path / "cache"
        manager = FileCacheManager(cache_dir=str(cache_dir))
        result = AnalysisResult(
            file_path="sample.py",
            file_size=10,
            analysis_status="completed",
            vulnerabilities=[],
            security_score=100,
            recommendations=[],
            analysis_time=0.1,
        )

        manager.cache_result("../evil", result)

        assert manager.get_cached_result("../evil") is None
        assert manager.is_cache_valid(tmp_path / "sample.py", "../evil") is False
        assert list(cache_dir.rglob("*.json")) == []
