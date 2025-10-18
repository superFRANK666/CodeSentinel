#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for interfaces and data models
"""

import pytest
from datetime import datetime

from src.core.interfaces import (
    Vulnerability, AnalysisResult, ScanSummary, SeverityLevel,
    AnalyzerConfig, ReportConfig, SecurityConfig, AppConfig
)


class TestDataModels:
    """Test cases for data models"""

    def test_vulnerability_creation(self):
        """Test Vulnerability data model creation"""
        vulnerability = Vulnerability(
            type="SQL Injection",
            severity=SeverityLevel.HIGH,
            line=10,
            description="SQL injection vulnerability found",
            remediation="Use parameterized queries",
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            confidence=0.95,
            cwe_id="CWE-89",
            owasp_category="A03:2021 – Injection"
        )

        assert vulnerability.type == "SQL Injection"
        assert vulnerability.severity == SeverityLevel.HIGH
        assert vulnerability.line == 10
        assert vulnerability.confidence == 0.95
        assert vulnerability.cwe_id == "CWE-89"

    def test_vulnerability_defaults(self):
        """Test Vulnerability default values"""
        vulnerability = Vulnerability(
            type="Test",
            severity=SeverityLevel.LOW,
            line=1,
            description="Test",
            remediation="Test",
            code_snippet="Test"
        )

        assert vulnerability.confidence == 0.8  # Default value
        assert vulnerability.cwe_id is None  # Default value
        assert vulnerability.owasp_category is None  # Default value

    def test_analysis_result_creation(self):
        """Test AnalysisResult data model creation"""
        vulnerabilities = [
            Vulnerability(
                type="Test Vulnerability",
                severity=SeverityLevel.MEDIUM,
                line=5,
                description="Test description",
                remediation="Test remediation",
                code_snippet="test code"
            )
        ]

        result = AnalysisResult(
            file_path="/test/file.py",
            file_size=1024,
            analysis_status="completed",
            vulnerabilities=vulnerabilities,
            security_score=75,
            recommendations=["Fix the vulnerability"],
            analysis_time=2.5,
            pre_analysis_info={"lines": 50}
        )

        assert result.file_path == "/test/file.py"
        assert result.file_size == 1024
        assert result.analysis_status == "completed"
        assert len(result.vulnerabilities) == 1
        assert result.security_score == 75
        assert result.analysis_time == 2.5
        assert result.pre_analysis_info["lines"] == 50

    def test_scan_summary_creation(self):
        """Test ScanSummary data model creation"""
        severity_counts = {
            "low": 5,
            "medium": 3,
            "high": 2,
            "critical": 1
        }

        summary = ScanSummary(
            total_files=10,
            scan_time=15.5,
            total_vulnerabilities=11,
            severity_counts=severity_counts,
            files_with_issues=8,
            analysis_engine="TestAnalyzer",
            scan_timestamp=datetime.now().isoformat()
        )

        assert summary.total_files == 10
        assert summary.scan_time == 15.5
        assert summary.total_vulnerabilities == 11
        assert summary.files_with_issues == 8
        assert summary.analysis_engine == "TestAnalyzer"
        assert summary.severity_counts == severity_counts

    def test_severity_level_enum(self):
        """Test SeverityLevel enum values"""
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.CRITICAL.value == "critical"

    def test_analyzer_config_defaults(self):
        """Test AnalyzerConfig default values"""
        config = AnalyzerConfig()

        assert config.severity_threshold == SeverityLevel.LOW
        assert config.max_file_size == 1024 * 1024  # 1MB
        assert config.concurrent_limit == 5
        assert config.cache_enabled is True
        assert config.cache_ttl == 3600
        assert config.ai_model == "gpt-4o-mini"
        assert config.api_timeout == 60
        assert config.max_retries == 3
        assert config.base_url is None

    def test_analyzer_config_custom_values(self):
        """Test AnalyzerConfig with custom values"""
        config = AnalyzerConfig(
            severity_threshold=SeverityLevel.HIGH,
            max_file_size=2 * 1024 * 1024,  # 2MB
            concurrent_limit=10,
            cache_enabled=False,
            ai_model="gpt-4",
            base_url="https://api.openai.com"
        )

        assert config.severity_threshold == SeverityLevel.HIGH
        assert config.max_file_size == 2 * 1024 * 1024
        assert config.concurrent_limit == 10
        assert config.cache_enabled is False
        assert config.ai_model == "gpt-4"
        assert config.base_url == "https://api.openai.com"

    def test_report_config_defaults(self):
        """Test ReportConfig default values"""
        config = ReportConfig()

        assert config.formats == ["console", "markdown"]
        assert config.output_dir == "./reports"
        assert config.include_code_snippets is True
        assert config.include_remediation is True
        assert config.max_vulnerabilities == 1000

    def test_report_config_custom_values(self):
        """Test ReportConfig with custom values"""
        config = ReportConfig(
            formats=["json", "html"],
            output_dir="/custom/reports",
            include_code_snippets=False,
            max_vulnerabilities=500
        )

        assert config.formats == ["json", "html"]
        assert config.output_dir == "/custom/reports"
        assert config.include_code_snippets is False
        assert config.max_vulnerabilities == 500

    def test_security_config_defaults(self):
        """Test SecurityConfig default values"""
        config = SecurityConfig()

        assert config.enable_privacy_check is True
        assert config.enable_code_sanitization is False
        assert config.allowed_file_extensions == [".py"]
        assert config.blocked_patterns == ["*.pyc", "__pycache__", "*.so", "*.dll"]

    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values"""
        config = SecurityConfig(
            enable_privacy_check=False,
            enable_code_sanitization=True,
            allowed_file_extensions=[".py", ".js", ".ts"],
            blocked_patterns=["*.log", "*.tmp"]
        )

        assert config.enable_privacy_check is False
        assert config.enable_code_sanitization is True
        assert config.allowed_file_extensions == [".py", ".js", ".ts"]
        assert config.blocked_patterns == ["*.log", "*.tmp"]

    def test_app_config_defaults(self):
        """Test AppConfig default values"""
        config = AppConfig()

        assert isinstance(config.analyzer, AnalyzerConfig)
        assert isinstance(config.report, ReportConfig)
        assert isinstance(config.security, SecurityConfig)

    def test_app_config_with_configs(self):
        """Test AppConfig initialization with config objects"""
        analyzer_config = AnalyzerConfig(
            severity_threshold=SeverityLevel.HIGH,
            max_file_size=2048000
        )
        report_config = ReportConfig(formats=["json"])
        security_config = SecurityConfig(enable_privacy_check=False)

        config = AppConfig(
            analyzer=analyzer_config,
            report=report_config,
            security=security_config
        )

        assert config.analyzer.severity_threshold == SeverityLevel.HIGH
        assert config.analyzer.max_file_size == 2048000
        assert config.report.formats == ["json"]
        assert config.security.enable_privacy_check is False