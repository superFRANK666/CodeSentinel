#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for LargeFileAnalyzer chunking behavior
"""

from src.core.analyzers.large_file_analyzer import LargeFileAnalyzer


class TestLargeFileAnalyzerChunking:
    """Test cases for large file chunk splitting."""

    def test_split_content_small_file_terminates_with_single_chunk(self):
        """Small files should not loop because of overlap."""
        analyzer = LargeFileAnalyzer(chunk_size=5000, overlap=100)
        content = "def hello():\n    return 'world'"

        chunks = analyzer._split_content_into_chunks(content)

        assert len(chunks) == 1
        assert chunks[0]["start_line"] == 1
        assert chunks[0]["end_line"] == 2
        assert chunks[0]["content"] == content

    def test_split_content_with_overlap_makes_forward_progress(self):
        """Overlapping chunks should keep strictly advancing."""
        analyzer = LargeFileAnalyzer(chunk_size=5, overlap=2)
        content = "\n".join(f"value_{index} = {index}" for index in range(12))

        chunks = analyzer._split_content_into_chunks(content)
        start_lines = [chunk["start_line"] for chunk in chunks]

        assert chunks[-1]["end_line"] == 12
        assert len(chunks) == 4
        assert start_lines == sorted(start_lines)
        assert len(set(start_lines)) == len(start_lines)
