#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pytest configuration and fixtures
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any

from src.core.interfaces import AnalysisResult, Vulnerability, SeverityLevel


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file for testing"""
    python_file = temp_dir / "sample.py"
    python_file.write_text("""
import os
import subprocess

def vulnerable_function(user_input):
    # Potential command injection vulnerability
    os.system(f"echo {user_input}")

    # Potential SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def safe_function(user_input):
    # Safe input handling
    sanitized_input = user_input.replace("'", "''")
    query = f"SELECT * FROM users WHERE name = '{sanitized_input}'"
    return query

class ExampleClass:
    def __init__(self):
        self.data = "sensitive_data"

    def expose_data(self):
        return self.data
""")
    return python_file


@pytest.fixture
def sample_javascript_file(temp_dir):
    """Create a sample JavaScript file for testing"""
    js_file = temp_dir / "sample.js"
    js_file.write_text("""
const fs = require('fs');
const exec = require('child_process').exec;

function vulnerableFunction(userInput) {
    // Potential command injection
    exec(`echo ${userInput}`, (error, stdout, stderr) => {
        console.log(stdout);
    });

    // Potential XSS
    document.innerHTML = userInput;
}

function safeFunction(userInput) {
    // Safe input handling
    const sanitizedInput = userInput.replace(/</g, '&lt;');
    document.innerHTML = sanitizedInput;
}

class ExampleClass {
    constructor() {
        this.data = 'sensitive_data';
    }

    exposeData() {
        return this.data;
    }
}
""")
    return js_file


@pytest.fixture
def sample_analysis_result():
    """Create a sample analysis result for testing"""
    return AnalysisResult(
        file_path="/test/sample.py",
        file_size=1024,
        analysis_status="completed",
        vulnerabilities=[
            Vulnerability(
                type="Command Injection",
                severity=SeverityLevel.HIGH,
                line=5,
                description="Potential command injection vulnerability",
                remediation="Use subprocess.run with proper argument escaping",
                code_snippet="os.system(f\"echo {user_input}\")",
                confidence=0.9,
                cwe_id="CWE-78",
                owasp_category="A03:2021 – Injection"
            )
        ],
        security_score=65,
        recommendations=[
            "Use subprocess.run instead of os.system",
            "Implement input validation and sanitization"
        ],
        analysis_time=1.23,
        pre_analysis_info={
            "total_lines": 20,
            "code_lines": 15,
            "function_definitions": [
                {"line": 4, "name": "vulnerable_function", "full_definition": "def vulnerable_function(user_input):"}
            ]
        }
    )


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing"""
    return {
        "analyzer": {
            "severity_threshold": "low",
            "max_file_size": 1048576,
            "concurrent_limit": 5,
            "cache_enabled": True,
            "ai_model": "gpt-4o-mini"
        },
        "report": {
            "formats": ["console", "markdown"],
            "output_dir": "./reports",
            "include_code_snippets": True
        },
        "security": {
            "enable_privacy_check": True,
            "allowed_file_extensions": [".py", ".js"]
        }
    }