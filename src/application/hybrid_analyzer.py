#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
混合分析器 - 结合AI分析和本地规则
提供最佳的分析准确性和性能
"""

import asyncio
import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..core.interfaces import ICodeAnalyzer, AnalysisResult, Vulnerability, SeverityLevel
from ..core.analyzers.base_analyzer import BaseCodeAnalyzer


logger = logging.getLogger(__name__)


class HybridCodeAnalyzer(BaseCodeAnalyzer, ICodeAnalyzer):
    """混合分析器 - 结合AI和本地分析的优势"""

    def __init__(self, ai_analyzer: ICodeAnalyzer, local_analyzer: ICodeAnalyzer, max_concurrency: int = 5):
        super().__init__()
        self.name = "HybridCodeAnalyzer"
        self.version = "1.0.0"
        self.ai_analyzer = ai_analyzer
        self.local_analyzer = local_analyzer
        self.confidence_threshold = 0.8  # 置信度阈值
        self.analysis_strategy = AnalysisStrategy()  # 初始化策略引擎
        self.max_concurrency = max_concurrency  # 最大并发数，可配置

    async def analyze_file(self, file_path: Path,
                           severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """混合分析单个文件"""
        try:
            logger.info(f"开始混合分析文件: {file_path}")
            start_time = asyncio.get_event_loop().time()

            # 首先进行本地快速分析
            local_result = await self.local_analyzer.analyze_file(file_path, severity_filter)

            # 根据本地分析结果决定是否需要AI深度分析
            if self._should_use_ai_analysis(local_result):
                logger.info(f"本地分析发现高风险问题，启动AI深度分析: {file_path}")
                ai_result = await self.ai_analyzer.analyze_file(file_path, severity_filter)
                final_result = self._merge_results(local_result, ai_result)
            else:
                logger.info(f"本地分析未发现高风险问题，使用本地结果: {file_path}")
                final_result = local_result

            # 计算分析时间
            end_time = asyncio.get_event_loop().time()
            final_result.analysis_time = end_time - start_time

            return final_result

        except Exception as e:
            logger.error(f"混合分析文件失败 {file_path}: {e}.")
            # 如果混合分析失败，回退到本地分析
            return await self.local_analyzer.analyze_file(file_path, severity_filter)

    async def analyze_batch(self, file_paths: List[Path],
                            severity_filter: SeverityLevel = SeverityLevel.LOW) -> List[AnalysisResult]:
        """批量混合分析"""
        semaphore = asyncio.Semaphore(self.max_concurrency)  # 使用可配置的并发数

        async def analyze_with_semaphore(file_path: Path) -> AnalysisResult:
            async with semaphore:
                return await self.analyze_file(file_path, severity_filter)

        # 并发分析所有文件
        tasks = [analyze_with_semaphore(fp) for fp in file_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果 - analyze_file 已经包含了回退逻辑
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"文件分析完全失败 {file_paths[i]}: {result}")
                # 创建一个失败的结果对象，而不是重复回退
                error_result = AnalysisResult(
                    file_path=file_paths[i],
                    file_size=0,
                    analysis_status="failed",
                    vulnerabilities=[],
                    security_score=-1,
                    recommendations=[f"文件分析失败: {result}"],
                    analysis_time=0.0,
                    pre_analysis_info={"error": str(result)}
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        return processed_results

    def _should_use_ai_analysis(self, local_result: AnalysisResult) -> bool:
        """判断是否需要AI深度分析 - 统一使用策略引擎"""
        # 构建文件信息
        file_info = {
            'size': local_result.file_size,
            'path': local_result.file_path,
            'is_sensitive': self._is_sensitive_file(local_result.file_path)
        }

        # 统一使用策略引擎进行决策
        return self.analysis_strategy.should_use_ai_analysis(file_info, local_result, self.confidence_threshold)

    def _is_sensitive_file(self, file_path: str) -> bool:
        """判断是否为敏感文件"""
        sensitive_patterns = [
            'config', 'secret', 'key', 'password', 'credential',
            'auth', 'token', 'private', 'admin'
        ]
        file_name = Path(file_path).name.lower()
        return any(pattern in file_name for pattern in sensitive_patterns)

    def _merge_results(self, local_result: AnalysisResult, ai_result: AnalysisResult) -> AnalysisResult:
        """合并本地和AI分析结果"""
        # 去重合并漏洞
        all_vulnerabilities = local_result.vulnerabilities + ai_result.vulnerabilities
        merged_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)

        # 合并推荐建议
        all_recommendations = list(set(
            local_result.recommendations + ai_result.recommendations
        ))

        # 计算综合安全评分 - 使用更智能的合并逻辑
        security_score = self._calculate_merged_security_score(local_result.security_score, ai_result.security_score)

        # 合并预分析信息
        merged_pre_analysis = {
            **local_result.pre_analysis_info,
            "ai_analysis": {
                "model_info": getattr(self.ai_analyzer, 'model', 'unknown'),
                "analysis_timestamp": asyncio.get_event_loop().time()
            }
        }

        return AnalysisResult(
            file_path=local_result.file_path,
            file_size=local_result.file_size,
            analysis_status="completed",
            vulnerabilities=merged_vulnerabilities,
            security_score=security_score,
            recommendations=all_recommendations,
            analysis_time=local_result.analysis_time + ai_result.analysis_time,
            pre_analysis_info=merged_pre_analysis
        )

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """去重漏洞，优先保留AI分析结果"""
        seen = {}
        deduplicated = []

        for vuln in vulnerabilities:
            # 使用类型、行号和严重度作为去重键
            key = (vuln.type, vuln.line, vuln.severity)

            if key not in seen:
                seen[key] = vuln
                deduplicated.append(vuln)
            else:
                # 如果已存在，选择置信度更高的
                existing = seen[key]
                if vuln.confidence > existing.confidence:
                    # 替换为置信度更高的结果
                    deduplicated.remove(existing)
                    deduplicated.append(vuln)
                    seen[key] = vuln

        return deduplicated

    def _calculate_merged_security_score(self, local_score: int, ai_score: int) -> int:
        """计算合并后的安全评分"""
        # 如果AI分析失败，使用本地评分
        if ai_score == -1:
            return local_score

        # 如果本地分析失败，使用AI评分
        if local_score == -1:
            return ai_score

        # 如果本地评分和AI评分差异很大，取更保守的评分
        score_diff = abs(local_score - ai_score)
        if score_diff > 20:
            # 差异较大，取更保守的评分（更低的分数）
            return min(local_score, ai_score)
        else:
            # 差异较小，取平均值
            return (local_score + ai_score) // 2

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        local_info = self.local_analyzer.get_analyzer_info()
        ai_info = self.ai_analyzer.get_analyzer_info()

        return {
            "name": self.name,
            "version": self.version,
            "description": "混合分析器 - 结合AI和本地分析的优势",
            "components": {
                "local": local_info,
                "ai": ai_info
            },
            "features": [
                "智能分析策略",
                "双重验证机制",
                "动态置信度评估",
                "最佳性能和准确性平衡",
                "自动降级处理"
            ],
            "confidence_threshold": self.confidence_threshold,
            "status": "active"
        }


# 智能分析策略
class AnalysisStrategy:
    """分析策略类 - 统一的分析决策逻辑"""

    @staticmethod
    def should_use_ai_analysis(file_info: Dict[str, Any],
                              local_result: AnalysisResult,
                              confidence_threshold: float) -> bool:
        """统一判断是否需要AI深度分析"""

        # 1. 高危漏洞策略
        high_risk_vulnerabilities = [
            vuln for vuln in local_result.vulnerabilities
            if vuln.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        ]
        if high_risk_vulnerabilities:
            return True

        # 2. 置信度策略
        low_confidence_vulnerabilities = [
            vuln for vuln in local_result.vulnerabilities
            if vuln.confidence < confidence_threshold
        ]
        if len(low_confidence_vulnerabilities) > 0:
            return True

        # 3. 文件大小策略
        if file_info.get('size', 0) > 10000:  # 10KB以上的文件
            return True

        # 4. 敏感文件策略
        if file_info.get('is_sensitive', False):
            return True

        # 5. 代码复杂度策略
        if local_result.pre_analysis_info:
            ast_info = local_result.pre_analysis_info.get('ast_analysis', {})
            complexity_score = ast_info.get('complexity_score', 0)
            if complexity_score > 50:  # 复杂度阈值
                return True

            # 危险节点策略
            dangerous_nodes = ast_info.get('potential_dangerous_nodes', [])
            if len(dangerous_nodes) > 3:
                return True

            # 函数数量策略
            functions = local_result.pre_analysis_info.get('function_definitions', [])
            if len(functions) > 20:  # 函数数量较多
                return True

        return False

    @staticmethod
    def should_use_ai_heavy_analysis(file_info: Dict[str, Any],
                                     local_result: AnalysisResult) -> bool:
        """判断是否应该使用深度AI分析 - 保留向后兼容"""
        return AnalysisStrategy.should_use_ai_analysis(file_info, local_result, 0.8)

    @staticmethod
    def estimate_analysis_complexity(file_path: Path, content: str) -> Dict[str, Any]:
        """估算分析复杂度"""
        lines = content.split('\n')
        complexity_factors = {
            'line_count': len(lines),
            'code_lines': len([line for line in lines if line.strip() and not line.strip().startswith('#')]),
            'import_count': len([line for line in lines if line.strip().startswith(('import ', 'from '))]),
            'function_count': content.count('def '),
            'class_count': content.count('class '),
            'control_structures': content.count(('if ', 'for ', 'while ')),
            'string_literals': len(re.findall(r'["\'].*?["\']', content))
        }

        # 计算复杂度分数
        complexity_score = (
            complexity_factors['code_lines'] * 0.1
            + complexity_factors['function_count'] * 2
            + complexity_factors['class_count'] * 3
            + complexity_factors['control_structures'] * 1.5
            + complexity_factors['string_literals'] * 0.05
        )

        complexity_factors['complexity_score'] = complexity_score
        complexity_factors['analysis_difficulty'] = (
            'high' if complexity_score > 100 else
            'medium' if complexity_score > 50 else
            'low'
        )

        return complexity_factors

    @staticmethod
    def select_optimal_analyzer(file_info: Dict[str, Any],
                                user_preferences: Dict[str, Any]) -> str:
        """选择最优的分析器"""
        # 用户偏好
        prefer_speed = user_preferences.get('prefer_speed', False)
        prefer_accuracy = user_preferences.get('prefer_accuracy', True)
        privacy_required = user_preferences.get('privacy_required', False)

        # 文件特征
        file_size = file_info.get('size', 0)
        is_sensitive = file_info.get('is_sensitive', False)

        # 决策逻辑
        if privacy_required or is_sensitive:
            return "local"  # 隐私优先，使用本地分析

        if prefer_speed and file_size < 10000:  # <10KB
            return "local"  # 小文件，本地分析更快

        if prefer_accuracy or file_size > 30000:  # >30KB
            return "hybrid"  # 需要准确性或大文件，使用混合分析

        # 默认使用混合分析
        return "hybrid"
