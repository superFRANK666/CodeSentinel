#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for TaintAnalyzer
"""

import ast

import pytest

from src.core.analyzers.taint_analyzer import TaintAnalyzer


class TestTaintAnalyzer:
    """Test cases for taint flow analysis."""

    def test_detects_taint_flow_through_assignment_alias(self):
        """Taint should propagate through simple variable assignments."""
        code = """
import os

cmd = input("command: ")
alias = cmd
os.system(alias)
"""
        analyzer = TaintAnalyzer()
        flows = analyzer.analyze_taint_flows(ast.parse(code), code)

        assert len(flows) == 1
        assert flows[0].source.name == "alias"
        assert flows[0].sink == "os.system"
        assert flows[0].sink_line == 6
        assert flows[0].confidence == pytest.approx(0.855)
