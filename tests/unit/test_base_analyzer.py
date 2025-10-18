#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for BaseCodeAnalyzer
"""

import pytest
from pathlib import Path

from src.core.analyzers.base_analyzer import BaseCodeAnalyzer
from src.core.interfaces import AnalysisResult


class TestBaseCodeAnalyzer:
    """Test cases for BaseCodeAnalyzer"""

    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        analyzer = BaseCodeAnalyzer()
        assert analyzer.name == "BaseCodeAnalyzer"
        assert analyzer.version == "1.0.0"

    def test_read_file_safely_valid_file(self, sample_python_file):
        """Test reading a valid file safely"""
        analyzer = BaseCodeAnalyzer()
        content = analyzer._read_file_safely(sample_python_file)
        assert content is not None
        assert "def vulnerable_function" in content

    def test_read_file_safely_nonexistent_file(self):
        """Test reading a non-existent file"""
        analyzer = BaseCodeAnalyzer()
        content = analyzer._read_file_safely(Path("/nonexistent/file.py"))
        assert content is None

    def test_read_file_safely_too_large_file(self, temp_dir):
        """Test reading a file that's too large"""
        large_file = temp_dir / "large.py"
        # Create a file larger than 10MB
        large_content = "x" * (11 * 1024 * 1024)
        large_file.write_text(large_content)

        analyzer = BaseCodeAnalyzer()
        content = analyzer._read_file_safely(large_file)
        assert content is None

    def test_validate_python_syntax_valid_code(self):
        """Test validating valid Python syntax"""
        analyzer = BaseCodeAnalyzer()
        valid_code = "def hello():\n    return 'world'"
        assert analyzer._validate_python_syntax(valid_code) is True

    def test_validate_python_syntax_invalid_code(self):
        """Test validating invalid Python syntax"""
        analyzer = BaseCodeAnalyzer()
        invalid_code = "def hello()\n    return 'world'"  # Missing colon
        assert analyzer._validate_python_syntax(invalid_code) is False

    def test_pre_analyze_content(self, sample_python_file):
        """Test pre-analysis of code content"""
        analyzer = BaseCodeAnalyzer()
        content = sample_python_file.read_text()
        analysis = analyzer._pre_analyze_content(content)

        # Check that we got a PreAnalysisInfo object
        assert hasattr(analysis, 'total_lines')
        assert hasattr(analysis, 'code_lines')
        assert hasattr(analysis, 'import_statements')
        assert hasattr(analysis, 'function_definitions')
        assert hasattr(analysis, 'class_definitions')
        assert hasattr(analysis, 'complexity_metrics')
        assert hasattr(analysis, 'ast_info')

        # Check specific content
        assert analysis.total_lines > 0
        assert len(analysis.function_definitions) >= 2  # vulnerable_function, safe_function
        assert len(analysis.class_definitions) >= 1  # ExampleClass

    def test_analyze_ast(self):
        """Test AST analysis functionality"""
        analyzer = BaseCodeAnalyzer()
        code = """
def test_function(x, y):
    if x > 0:
        return y * 2
    return 0

class TestClass:
    def method(self):
        pass
"""
        import ast
        tree = ast.parse(code)
        ast_info = analyzer._analyze_ast(tree)

        # Check that we got an ASTInfo object
        assert hasattr(ast_info, 'functions')
        assert hasattr(ast_info, 'classes')
        assert hasattr(ast_info, 'imports')
        assert hasattr(ast_info, 'calls')
        assert hasattr(ast_info, 'complexity_score')

        # Check specific findings
        assert len(ast_info.functions) >= 1
        assert len(ast_info.classes) >= 1
        assert ast_info.complexity_score >= 0

    def test_calculate_complexity_metrics(self):
        """Test complexity metrics calculation"""
        analyzer = BaseCodeAnalyzer()
        code = """
# This is a comment
def function_with_complexity():
    if True:
        for i in range(10):
            if i % 2 == 0:
                continue
    return None
"""
        lines = code.split('\n')
        metrics = analyzer._calculate_complexity_metrics(code, lines)

        # Check that we got a ComplexityMetrics object
        assert hasattr(metrics, 'cyclomatic_complexity')
        assert hasattr(metrics, 'lines_of_code')
        assert hasattr(metrics, 'comment_lines')
        assert hasattr(metrics, 'blank_lines')

        assert metrics.lines_of_code > 0
        assert metrics.cyclomatic_complexity >= 0

    def test_create_error_result(self):
        """Test creation of error results"""
        analyzer = BaseCodeAnalyzer()
        file_path = Path("/test/file.py")
        error_message = "Test error"

        result = analyzer._create_error_result(file_path, error_message)

        assert isinstance(result, AnalysisResult)
        assert result.file_path == str(file_path)
        assert result.analysis_status == "error"
        assert result.security_score == 0
        assert len(result.vulnerabilities) == 0
        assert error_message in result.recommendations[0]

    def test_get_analyzer_info(self):
        """Test getting analyzer information"""
        analyzer = BaseCodeAnalyzer()
        info = analyzer.get_analyzer_info()

        assert "name" in info
        assert "version" in info
        assert "description" in info
        assert "features" in info

        assert info["name"] == "BaseCodeAnalyzer"
        assert info["version"] == "1.0.0"
        assert len(info["features"]) > 0