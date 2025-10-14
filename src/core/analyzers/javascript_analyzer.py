#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JavaScript代码分析器
通过ESLint进行JavaScript代码安全分析
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List

from .base_analyzer import BaseCodeAnalyzer
from ...core.interfaces import ICodeAnalyzer, AnalysisResult, SeverityLevel, Vulnerability
from ...infrastructure.external_analyzers import (
    run_eslint_analysis,
    check_eslint_availability,
    get_eslint_version,
    ExternalAnalyzerError
)

logger = logging.getLogger(__name__)


class JavaScriptAnalyzer(BaseCodeAnalyzer, ICodeAnalyzer):
    """JavaScript代码分析器"""

    def __init__(self):
        super().__init__()
        self.name = "JavaScriptAnalyzer"
        self.version = "1.0.0"
        self.supported_extensions = ['.js', '.jsx', '.mjs', '.cjs']
        self.eslint_available = False
        self.eslint_version = None

        # 检查ESLint可用性
        self._check_eslint_status()

    def _check_eslint_status(self):
        """检查ESLint状态"""
        self.eslint_available = check_eslint_availability()
        if self.eslint_available:
            self.eslint_version = get_eslint_version()
            logger.info(f"ESLint可用，版本: {self.eslint_version}")
        else:
            self.eslint_version = None
            logger.warning("ESLint不可用，JavaScript分析功能将被禁用")
            # 提供安装指导
            from ...infrastructure.external_analyzers import install_eslint_dependencies
            logger.warning("请安装ESLint以启用JavaScript分析功能:")
            install_eslint_dependencies()

    async def analyze_file(self, file_path: Path,
                          severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """分析单个JavaScript文件"""
        start_time = asyncio.get_event_loop().time()

        try:
            logger.info(f"开始分析JavaScript文件: {file_path}")

            # 检查文件扩展名
            if not self._is_supported_file(file_path):
                return self._create_error_result(
                    file_path,
                    f"不支持的文件类型。支持的类型: {', '.join(self.supported_extensions)}"
                )

            # 检查ESLint可用性
            if not self.eslint_available:
                return self._create_error_result(
                    file_path,
                    "ESLint不可用。请安装ESLint: npm install -g eslint eslint-plugin-security"
                )

            # 检查文件是否存在
            if not file_path.exists():
                return self._create_error_result(
                    file_path,
                    "文件不存在"
                )

            # 获取文件大小
            file_size = file_path.stat().st_size

            # 进行基础分析
            pre_analysis_info = self._perform_basic_analysis(file_path)

            # 使用ESLint进行安全分析
            vulnerabilities = await self._run_eslint_analysis_async(file_path)

            # 根据严重程度过滤漏洞
            filtered_vulnerabilities = self._filter_vulnerabilities_by_severity(
                vulnerabilities, severity_filter
            )

            # 计算安全评分
            security_score = self._calculate_security_score(filtered_vulnerabilities)

            # 生成建议
            recommendations = self._generate_recommendations(filtered_vulnerabilities)

            # 计算分析时间
            end_time = asyncio.get_event_loop().time()
            analysis_time = end_time - start_time

            return AnalysisResult(
                file_path=str(file_path),
                file_size=file_size,
                analysis_status="completed",
                vulnerabilities=filtered_vulnerabilities,
                security_score=security_score,
                recommendations=recommendations,
                analysis_time=analysis_time,
                pre_analysis_info=pre_analysis_info
            )

        except Exception as e:
            logger.error(f"分析JavaScript文件失败 {file_path}: {e}")
            return self._create_error_result(file_path, str(e))

    async def analyze_batch(self, file_paths: List[Path],
                           severity_filter: SeverityLevel = SeverityLevel.LOW) -> List[AnalysisResult]:
        """批量分析JavaScript文件"""
        logger.info(f"开始批量分析 {len(file_paths)} 个JavaScript文件")

        # 并发限制
        semaphore = asyncio.Semaphore(5)

        async def analyze_with_semaphore(file_path: Path) -> AnalysisResult:
            async with semaphore:
                return await self.analyze_file(file_path, severity_filter)

        # 并发执行分析
        tasks = [analyze_with_semaphore(fp) for fp in file_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量分析中文件 {file_paths[i]} 发生异常: {result}")
                error_result = self._create_error_result(
                    file_paths[i],
                    f"分析过程中发生异常: {str(result)}"
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        logger.info(f"批量分析完成，共处理 {len(processed_results)} 个文件")
        return processed_results

    def _is_supported_file(self, file_path: Path) -> bool:
        """检查文件是否支持"""
        return file_path.suffix.lower() in self.supported_extensions

    def _perform_basic_analysis(self, file_path: Path) -> Dict[str, Any]:
        """执行基础分析"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            lines = content.split('\n')

            # 基础统计信息
            basic_info = {
                'total_lines': len(lines),
                'code_lines': len([line for line in lines if line.strip() and not line.strip().startswith('//')]),
                'comment_lines': len([line for line in lines if line.strip().startswith('//')]),
                'blank_lines': len([line for line in lines if not line.strip()]),
                'file_extension': file_path.suffix.lower(),
                'eslint_available': self.eslint_available,
                'eslint_version': self.eslint_version
            }

            # 简单的代码特征分析
            code_features = {
                'has_import_export': any('import ' in line or 'export ' in line for line in lines),
                'has_require': any('require(' in line for line in lines),
                'has_function_calls': any('(' in line and ')' in line for line in lines),
                'has_string_literals': any('"' in line or "'" in line for line in lines),
                'has_regex_literals': any('/' in line and ('/g' in line or '/i' in line or '/m' in line) for line in lines)
            }

            # 潜在风险模式检测
            risk_patterns = []
            risk_keywords = ['eval', 'Function', 'setTimeout', 'setInterval', 'document.write', 'innerHTML']
            for i, line in enumerate(lines, 1):
                for keyword in risk_keywords:
                    if keyword in line:
                        risk_patterns.append({
                            'line': i,
                            'keyword': keyword,
                            'content': line.strip()[:100]  # 限制长度
                        })

            return {
                'basic_info': basic_info,
                'code_features': code_features,
                'risk_patterns': risk_patterns,
                'analyzer_info': {
                    'name': self.name,
                    'version': self.version,
                    'type': 'external_tool_integration'
                }
            }

        except Exception as e:
            logger.warning(f"基础分析失败: {e}")
            return {
                'basic_info': {},
                'code_features': {},
                'risk_patterns': [],
                'analyzer_info': {
                    'name': self.name,
                    'version': self.version,
                    'type': 'external_tool_integration',
                    'error': str(e)
                }
            }

    async def _run_eslint_analysis_async(self, file_path: Path) -> List[Vulnerability]:
        """异步运行ESLint分析"""
        try:
            # 在线程池中运行ESLint分析（避免阻塞事件循环）
            loop = asyncio.get_event_loop()
            vulnerabilities = await loop.run_in_executor(
                None, run_eslint_analysis, file_path
            )
            return vulnerabilities

        except ExternalAnalyzerError as e:
            logger.error(f"ESLint分析失败: {e}")
            # 创建一个描述性错误作为"漏洞"返回
            error_vulnerability = Vulnerability(
                type="eslint_error",
                severity=SeverityLevel.MEDIUM,
                line=1,
                description=f"ESLint分析失败: {str(e)}",
                remediation="请确保ESLint已正确安装并且配置文件有效",
                code_snippet="",
                confidence=1.0
            )
            return [error_vulnerability]

        except Exception as e:
            logger.error(f"运行ESLint分析时发生异常: {e}")
            return []

    def _filter_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability],
                                           severity_filter: SeverityLevel) -> List[Vulnerability]:
        """根据严重程度过滤漏洞"""
        severity_order = {
            SeverityLevel.LOW: 0,
            SeverityLevel.MEDIUM: 1,
            SeverityLevel.HIGH: 2,
            SeverityLevel.CRITICAL: 3
        }

        filter_level = severity_order[severity_filter]
        filtered = [
            vuln for vuln in vulnerabilities
            if severity_order[vuln.severity] >= filter_level
        ]

        logger.debug(f"过滤前漏洞数量: {len(vulnerabilities)}, 过滤后: {len(filtered)}")
        return filtered

    def _calculate_security_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """计算安全评分"""
        if not vulnerabilities:
            return 100

        # 根据漏洞严重程度计算扣分
        score_deductions = {
            SeverityLevel.LOW: 5,
            SeverityLevel.MEDIUM: 15,
            SeverityLevel.HIGH: 30,
            SeverityLevel.CRITICAL: 50
        }

        total_deduction = 0
        for vuln in vulnerabilities:
            total_deduction += score_deductions.get(vuln.severity, 10)

        # 基础分数100分，减去总扣分，最低0分
        security_score = max(0, 100 - total_deduction)

        logger.debug(f"安全评分计算: 基础100 - 扣分{total_deduction} = {security_score}")
        return security_score

    def _generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """生成修复建议"""
        if not vulnerabilities:
            return ["未发现安全问题，代码安全性良好"]

        recommendations = []

        # 通用建议
        recommendations.append("建议定期运行ESLint检查以保持代码质量")
        recommendations.append("考虑集成CI/CD流程中的自动化安全检查")

        # 根据漏洞类型生成特定建议
        vulnerability_types = set(vuln.type for vuln in vulnerabilities)

        if 'no-eval' in vulnerability_types or 'security/detect-eval-with-expression' in vulnerability_types:
            recommendations.append("避免使用eval()函数，使用更安全的替代方案如JSON.parse()")

        if 'security/detect-object-injection' in vulnerability_types:
            recommendations.append("防止对象注入攻击，验证用户输入并避免使用动态属性名")

        if 'security/detect-pseudoRandomBytes' in vulnerability_types:
            recommendations.append("使用加密安全的随机数生成器，如crypto.randomBytes()")

        if 'no-script-url' in vulnerability_types:
            recommendations.append("避免使用javascript: URL，使用事件处理器代替")

        # 去重并返回
        return list(set(recommendations))

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "JavaScript代码安全分析器，基于ESLint",
            "supported_extensions": self.supported_extensions,
            "external_tool": {
                "name": "ESLint",
                "available": self.eslint_available,
                "version": self.eslint_version,
                "required": True
            },
            "features": [
                "ESLint集成",
                "安全规则检测",
                "代码质量检查",
                "异步分析支持",
                "批量处理能力"
            ],
            "security_rules": [
                "eval()检测",
                "代码注入防护",
                "XSS防护",
                "随机数生成安全",
                "文件系统安全",
                "正则表达式安全"
            ],
            "status": "active" if self.eslint_available else "disabled"
        }