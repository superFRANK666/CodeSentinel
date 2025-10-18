#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for MultiLanguageAnalyzer
"""

import pytest
from unittest.mock import Mock, AsyncMock
from pathlib import Path

from src.application.multi_language_analyzer import MultiLanguageAnalyzer
from src.core.interfaces import ICodeAnalyzer, AnalysisResult, SeverityLevel


class MockAnalyzer:
    """Mock analyzer for testing"""

    def __init__(self, name: str):
        self.name = name

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        return AnalysisResult(
            file_path=str(file_path),
            file_size=100,
            analysis_status="completed",
            vulnerabilities=[],
            security_score=100,
            recommendations=[],
            analysis_time=0.1,
            pre_analysis_info={
                "multi_language_info": {
                    "file_extension": file_path.suffix.lower(),
                    "analyzer_used": self.name,
                    "analyzer_type": "MockAnalyzer",
                }
            }
        )

    async def analyze_batch(self, file_paths: list, severity_filter: SeverityLevel = SeverityLevel.LOW) -> list:
        return [
            await self.analyze_file(fp, severity_filter)
            for fp in file_paths
        ]

    def get_analyzer_info(self) -> dict:
        return {
            "name": self.name,
            "version": "1.0.0",
            "description": "Mock analyzer"
        }


class TestMultiLanguageAnalyzer:
    """Test cases for MultiLanguageAnalyzer"""

    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        assert analyzer.name == "MultiLanguageAnalyzer"
        assert analyzer.version == "1.0.0"
        assert analyzer.python_analyzer == mock_python_analyzer
        assert len(analyzer.supported_extensions) > 0

    def test_supported_extensions(self):
        """Test supported file extensions"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        expected_extensions = {".py", ".pyw", ".pyi", ".js", ".jsx", ".mjs", ".cjs"}
        assert set(analyzer.supported_extensions) == expected_extensions

    def test_is_supported_file(self):
        """Test file support checking"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        # Supported files
        assert analyzer.is_supported_file(Path("test.py")) is True
        assert analyzer.is_supported_file(Path("test.js")) is True
        assert analyzer.is_supported_file(Path("test.jsx")) is True

        # Unsupported files
        assert analyzer.is_supported_file(Path("test.txt")) is False
        assert analyzer.is_supported_file(Path("test.java")) is False

    def test_get_analyzer_for_file(self):
        """Test getting analyzer for specific file"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        # Python files should get python analyzer
        python_analyzer = analyzer.get_analyzer_for_file(Path("test.py"))
        assert python_analyzer == mock_python_analyzer

        # JavaScript files should get javascript analyzer
        js_analyzer = analyzer.get_analyzer_for_file(Path("test.js"))
        assert js_analyzer == analyzer.javascript_analyzer

        # Unsupported files should return None
        unsupported_analyzer = analyzer.get_analyzer_for_file(Path("test.txt"))
        assert unsupported_analyzer is None

    @pytest.mark.asyncio
    async def test_analyze_file_supported_python(self, sample_python_file):
        """Test analyzing a supported Python file"""
        mock_python_analyzer = MockAnalyzer("PythonAnalyzer")
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        result = await analyzer.analyze_file(sample_python_file)

        assert result.analysis_status == "completed"
        assert result.file_path == str(sample_python_file)
        assert result.pre_analysis_info is not None
        assert "multi_language_info" in result.pre_analysis_info

        multi_info = result.pre_analysis_info["multi_language_info"]
        assert multi_info["file_extension"] == ".py"
        assert multi_info["analyzer_used"] == "PythonAnalyzer"
        assert multi_info["analyzer_type"] == "MockAnalyzer"

    @pytest.mark.asyncio
    async def test_analyze_file_unsupported_type(self, temp_dir):
        """Test analyzing an unsupported file type"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        # Create an unsupported file
        unsupported_file = temp_dir / "test.txt"
        unsupported_file.write_text("This is not a supported file type")

        result = await analyzer.analyze_file(unsupported_file)

        assert result.analysis_status == "unsupported"
        assert result.security_score == 0
        assert len(result.vulnerabilities) == 0
        assert "不支持的文件类型" in result.recommendations[0]

    @pytest.mark.asyncio
    async def test_analyze_file_with_exception(self, temp_dir):
        """Test handling exceptions during file analysis"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        mock_python_analyzer.analyze_file = AsyncMock(side_effect=Exception("Test error"))

        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        python_file = temp_dir / "test.py"
        python_file.write_text("def test(): pass")

        result = await analyzer.analyze_file(python_file)

        assert result.analysis_status == "error"
        assert result.security_score == 0
        assert "分析失败" in result.recommendations[0]

    @pytest.mark.asyncio
    async def test_analyze_batch_mixed_files(self, temp_dir):
        """Test batch analysis with mixed file types"""
        mock_python_analyzer = MockAnalyzer("PythonAnalyzer")
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        # Create Python file
        python_file = temp_dir / "test.py"
        python_file.write_text("def test(): pass")

        files = [python_file]
        results = await analyzer.analyze_batch(files)

        assert len(results) == 1
        assert all(result.analysis_status == "completed" for result in results)

        # Check Python file result
        python_result = results[0]
        multi_info = python_result.pre_analysis_info["multi_language_info"]
        assert multi_info["file_extension"] == ".py"

    @pytest.mark.asyncio
    async def test_analyze_batch_with_unsupported_files(self, temp_dir):
        """Test batch analysis with unsupported files"""
        mock_python_analyzer = MockAnalyzer("PythonAnalyzer")
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        # Create supported file
        python_file = temp_dir / "test.py"
        python_file.write_text("def test(): pass")

        files = [python_file]
        results = await analyzer.analyze_batch(files)

        assert len(results) == 1
        assert results[0].analysis_status == "completed"

    @pytest.mark.asyncio
    async def test_analyze_batch_with_exception(self, temp_dir):
        """Test batch analysis with exceptions"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        mock_python_analyzer.analyze_file = AsyncMock(side_effect=Exception("Test error"))
        mock_python_analyzer.analyze_batch = AsyncMock(side_effect=Exception("Test error"))

        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        # Create a Python file
        file_path = temp_dir / "test.py"
        file_path.write_text("def test(): pass")

        results = await analyzer.analyze_batch([file_path])

        assert len(results) == 1
        assert results[0].analysis_status == "error"
        assert "批量分析失败" in results[0].recommendations[0]

    def test_group_files_by_type(self):
        """Test file grouping by type"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        files = [
            Path("test1.py"),
            Path("test2.py"),
            Path("test3.js"),
            Path("test4.jsx"),
            Path("test5.txt"),  # unsupported
            Path("test6.py"),
        ]

        groups = analyzer._group_files_by_type(files)

        assert ".py" in groups
        assert ".js" in groups
        assert ".jsx" in groups
        assert ".txt" not in groups  # Should not include unsupported types

        assert len(groups[".py"]) == 3  # test1.py, test2.py, test6.py
        assert len(groups[".js"]) == 1  # test3.js
        assert len(groups[".jsx"]) == 1  # test4.jsx

    def test_get_analyzer_info(self):
        """Test getting analyzer information"""
        mock_python_analyzer = MockAnalyzer("PythonAnalyzer")
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        info = analyzer.get_analyzer_info()

        assert "name" in info
        assert "version" in info
        assert "description" in info
        assert "supported_languages" in info
        assert "supported_extensions" in info
        assert "features" in info
        assert "analyzers" in info

        assert info["name"] == "MultiLanguageAnalyzer"
        assert len(info["supported_languages"]) >= 2  # Python and JavaScript
        assert len(info["features"]) > 0
        assert len(info["analyzers"]) > 0

    def test_get_language_name(self):
        """Test language name mapping"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        assert analyzer._get_language_name(".py") == "Python"
        assert analyzer._get_language_name(".pyw") == "Python"
        assert analyzer._get_language_name(".js") == "JavaScript"
        assert analyzer._get_language_name(".jsx") == "JavaScript (React)"
        assert analyzer._get_language_name(".mjs") == "JavaScript (ES Module)"
        assert analyzer._get_language_name(".cjs") == "JavaScript (CommonJS)"
        assert analyzer._get_language_name(".unknown") == "Unknown"

    def test_get_supported_extensions(self):
        """Test getting supported extensions"""
        mock_python_analyzer = Mock(spec=ICodeAnalyzer)
        analyzer = MultiLanguageAnalyzer(mock_python_analyzer)

        extensions = analyzer.get_supported_extensions()

        assert isinstance(extensions, list)
        assert len(extensions) > 0
        assert ".py" in extensions
        assert ".js" in extensions

        # Ensure it returns a copy, not the original list
        extensions.append(".test")
        assert ".test" not in analyzer.supported_extensions