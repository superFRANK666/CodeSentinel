#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Core interface definition module
Defines abstract interfaces for all core components in the system, implementing dependency inversion principle
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Protocol
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """漏洞严重度等级"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Vulnerability:
    """安全漏洞数据模型"""

    type: str
    severity: SeverityLevel
    line: int
    description: str
    remediation: str
    code_snippet: str
    confidence: float = 0.8  # 检测置信度
    cwe_id: Optional[str] = None  # CWE编号
    owasp_category: Optional[str] = None  # OWASP分类


@dataclass
class AnalysisResult:
    """分析结果数据模型"""

    file_path: str
    file_size: int
    analysis_status: str
    vulnerabilities: List[Vulnerability]
    security_score: int  # 0-100
    recommendations: List[str]
    analysis_time: float
    pre_analysis_info: Optional[Dict[str, Any]] = None


@dataclass
class ScanSummary:
    """扫描摘要数据模型"""

    total_files: int
    scan_time: float
    total_vulnerabilities: int
    severity_counts: Dict[str, int]
    files_with_issues: int
    analysis_engine: str
    scan_timestamp: str


class ICodeAnalyzer(Protocol):
    """代码分析器接口"""

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """分析单个文件"""
        ...

    async def analyze_batch(
        self, file_paths: List[Path], severity_filter: SeverityLevel = SeverityLevel.LOW
    ) -> List[AnalysisResult]:
        """批量分析文件"""
        ...

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        ...


class IReportGenerator(Protocol):
    """报告生成器接口"""

    def generate_report(self, results: Dict[str, Any], output_path: Optional[str] = None) -> None:
        """生成报告"""
        ...


class IVulnerabilityDetector(Protocol):
    """漏洞检测器接口"""

    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        """检测代码中的漏洞"""
        ...

    def get_detector_info(self) -> Dict[str, Any]:
        """获取检测器信息"""
        ...


class IConfigManager(Protocol):
    """配置管理器接口"""

    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """加载配置"""
        ...

    def save_config(self, config: Dict[str, Any], config_path: str) -> None:
        """保存配置"""
        ...

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        ...

    def set(self, key: str, value: Any) -> None:
        """设置配置项"""
        ...


class ICacheManager(Protocol):
    """缓存管理器接口"""

    def get_cached_result(self, file_hash: str) -> Optional[AnalysisResult]:
        """获取缓存的分析结果"""
        ...

    def cache_result(self, file_hash: str, result: AnalysisResult) -> None:
        """缓存分析结果"""
        ...

    def is_cache_valid(self, file_path: Path, file_hash: str) -> bool:
        """检查缓存是否有效"""
        ...

    def clear_cache(self) -> None:
        """清空缓存"""
        ...


class IProgressReporter(Protocol):
    """进度报告器接口"""

    def start_progress(self, total: int, description: str = "") -> None:
        """开始进度报告"""
        ...

    def update_progress(self, current: int, message: str = "") -> None:
        """更新进度"""
        ...

    def finish_progress(self) -> None:
        """完成进度报告"""
        ...


class IPluginManager(Protocol):
    """插件管理器接口"""

    def load_plugins(self, plugin_dir: str) -> None:
        """加载插件"""
        ...

    def get_detector_plugins(self) -> List[IVulnerabilityDetector]:
        """获取检测器插件"""
        ...

    def get_reporter_plugins(self) -> List[IReportGenerator]:
        """获取报告生成器插件"""
        ...

    def register_plugin(self, plugin: Any) -> None:
        """注册插件"""
        ...


class IErrorHandler(Protocol):
    """错误处理器接口"""

    def handle_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """处理错误并返回友好的错误信息"""
        ...

    def get_error_suggestions(self, error_type: str) -> List[str]:
        """获取错误解决建议"""
        ...


class ICodePrivacyManager(Protocol):
    """代码隐私管理器接口"""

    def sanitize_code(self, content: str) -> str:
        """对代码进行脱敏处理"""
        ...

    def is_sensitive_content(self, content: str) -> bool:
        """检查是否包含敏感内容"""
        ...

    def get_privacy_level(self, content: str) -> str:
        """获取隐私等级"""
        ...


class IAuthenticationManager(Protocol):
    """认证管理器接口"""

    async def authenticate(self, api_key: str) -> bool:
        """用户认证"""
        ...

    def is_authenticated(self) -> bool:
        """检查是否已经认证"""
        ...

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """获取用户信息"""
        ...


# 配置数据模型
@dataclass
class AnalyzerConfig:
    """分析器配置"""

    severity_threshold: SeverityLevel = SeverityLevel.LOW
    max_file_size: int = 1024 * 1024  # 1MB
    concurrent_limit: int = 5
    cache_enabled: bool = True
    cache_ttl: int = 3600  # 1小时
    ai_model: str = "gpt-4o-mini"
    api_timeout: int = 60
    max_retries: int = 3
    base_url: Optional[str] = None


@dataclass
class ReportConfig:
    """报告配置"""

    formats: Optional[List[str]] = None
    output_dir: str = "./reports"
    include_code_snippets: bool = True
    include_remediation: bool = True
    max_vulnerabilities: int = 1000

    def __post_init__(self) -> None:
        if self.formats is None:
            self.formats = ["console", "markdown"]


@dataclass
class SecurityConfig:
    """安全配置"""

    enable_privacy_check: bool = True
    enable_code_sanitization: bool = False
    allowed_file_extensions: Optional[List[str]] = None
    blocked_patterns: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.allowed_file_extensions is None:
            self.allowed_file_extensions = [".py"]
        if self.blocked_patterns is None:
            self.blocked_patterns = ["*.pyc", "__pycache__", "*.so", "*.dll"]


@dataclass
class AppConfig:
    """应用配置"""

    analyzer: Optional[AnalyzerConfig] = None
    report: Optional[ReportConfig] = None
    security: Optional[SecurityConfig] = None

    def __post_init__(self) -> None:
        if self.analyzer is None:
            self.analyzer = AnalyzerConfig()

        if self.report is None:
            self.report = ReportConfig()

        if self.security is None:
            self.security = SecurityConfig()
