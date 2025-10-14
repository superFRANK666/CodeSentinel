#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多语言代码分析器
根据文件扩展名自动选择合适的分析器
"""

import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..core.interfaces import ICodeAnalyzer, AnalysisResult, SeverityLevel
from ..core.analyzers.javascript_analyzer import JavaScriptAnalyzer

logger = logging.getLogger(__name__)


class MultiLanguageAnalyzer(ICodeAnalyzer):
    """多语言代码分析器"""

    def __init__(self, python_analyzer: ICodeAnalyzer):
        self.name = "MultiLanguageAnalyzer"
        self.version = "1.0.0"
        self.python_analyzer = python_analyzer
        self.javascript_analyzer = JavaScriptAnalyzer()

        # 文件扩展名到分析器的映射
        self.analyzer_mapping = {
            # Python文件
            '.py': self.python_analyzer,
            '.pyw': self.python_analyzer,
            '.pyi': self.python_analyzer,

            # JavaScript文件
            '.js': self.javascript_analyzer,
            '.jsx': self.javascript_analyzer,
            '.mjs': self.javascript_analyzer,
            '.cjs': self.javascript_analyzer,
        }

        # 支持的文件扩展名
        self.supported_extensions = list(self.analyzer_mapping.keys())

    async def analyze_file(self, file_path: Path,
                          severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """分析单个文件，根据扩展名选择合适的分析器"""
        try:
            # 获取文件扩展名
            extension = file_path.suffix.lower()

            # 检查文件扩展名是否支持
            if extension not in self.analyzer_mapping:
                logger.warning(f"不支持的文件类型: {extension}")
                return self._create_unsupported_file_result(file_path, extension)

            # 选择合适的分析器
            analyzer = self.analyzer_mapping[extension]

            # 记录分析器选择
            logger.debug(f"文件 {file_path} 使用分析器: {analyzer.name}")

            # 执行分析
            result = await analyzer.analyze_file(file_path, severity_filter)

            # 添加多语言分析信息
            if result.pre_analysis_info is None:
                result.pre_analysis_info = {}

            result.pre_analysis_info['multi_language_info'] = {
                'file_extension': extension,
                'analyzer_used': analyzer.name,
                'analyzer_type': type(analyzer).__name__
            }

            return result

        except Exception as e:
            logger.error(f"多语言分析文件失败 {file_path}: {e}")
            return self._create_error_result(file_path, str(e))

    async def analyze_batch(self, file_paths: List[Path],
                           severity_filter: SeverityLevel = SeverityLevel.LOW) -> List[AnalysisResult]:
        """批量分析文件，根据文件类型分组并使用相应的分析器"""
        try:
            logger.info(f"开始多语言批量分析 {len(file_paths)} 个文件")

            # 按文件类型分组
            file_groups = self._group_files_by_type(file_paths)

            # 记录分组情况
            for extension, files in file_groups.items():
                logger.info(f"文件类型 {extension}: {len(files)} 个文件")

            # 使用相应的分析器分析每组文件
            all_results = []
            for extension, files in file_groups.items():
                if not files:
                    continue

                analyzer = self.analyzer_mapping[extension]
                logger.debug(f"使用 {analyzer.name} 分析 {len(files)} 个 {extension} 文件")

                try:
                    group_results = await analyzer.analyze_batch(files, severity_filter)
                    all_results.extend(group_results)
                except Exception as e:
                    logger.error(f"批量分析 {extension} 文件失败: {e}")
                    # 为该组文件创建错误结果
                    for file_path in files:
                        error_result = self._create_error_result(file_path, f"批量分析失败: {str(e)}")
                        all_results.append(error_result)

            logger.info(f"多语言批量分析完成，共处理 {len(all_results)} 个文件")
            return all_results

        except Exception as e:
            logger.error(f"多语言批量分析失败: {e}")
            # 返回所有文件的错误结果
            return [self._create_error_result(fp, str(e)) for fp in file_paths]

    def _group_files_by_type(self, file_paths: List[Path]) -> Dict[str, List[Path]]:
        """根据文件类型分组"""
        groups = {}

        for file_path in file_paths:
            extension = file_path.suffix.lower()

            # 检查是否支持该文件类型
            if extension in self.analyzer_mapping:
                if extension not in groups:
                    groups[extension] = []
                groups[extension].append(file_path)
            else:
                logger.warning(f"跳过不支持的文件类型: {file_path} ({extension})")

        return groups

    def _create_unsupported_file_result(self, file_path: Path, extension: str) -> AnalysisResult:
        """创建不支持的文件类型结果"""
        return AnalysisResult(
            file_path=str(file_path),
            file_size=0,
            analysis_status="unsupported",
            vulnerabilities=[],
            security_score=0,
            recommendations=[f"不支持的文件类型: {extension}。支持的类型: {', '.join(self.supported_extensions)}"],
            analysis_time=0.0,
            pre_analysis_info={
                'multi_language_info': {
                    'file_extension': extension,
                    'analyzer_used': 'none',
                    'analyzer_type': 'unsupported'
                }
            }
        )

    def _create_error_result(self, file_path: Path, error_message: str) -> AnalysisResult:
        """创建错误结果"""
        return AnalysisResult(
            file_path=str(file_path),
            file_size=0,
            analysis_status="error",
            vulnerabilities=[],
            security_score=0,
            recommendations=[f"分析失败: {error_message}"],
            analysis_time=0.0,
            pre_analysis_info={
                'multi_language_info': {
                    'file_extension': file_path.suffix.lower(),
                    'analyzer_used': 'none',
                    'analyzer_type': 'error',
                    'error': error_message
                }
            }
        )

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        supported_languages = []
        for ext, analyzer in self.analyzer_mapping.items():
            language_name = self._get_language_name(ext)
            if language_name not in [lang['name'] for lang in supported_languages]:
                supported_languages.append({
                    'name': language_name,
                    'extensions': [ext for ext, a in self.analyzer_mapping.items()
                                  if self._get_language_name(ext) == language_name],
                    'analyzer': analyzer.name
                })

        return {
            "name": self.name,
            "version": self.version,
            "description": "多语言代码安全分析器，根据文件类型自动选择分析器",
            "supported_languages": supported_languages,
            "supported_extensions": self.supported_extensions,
            "features": [
                "自动语言检测",
                "多语言支持",
                "智能分析器选择",
                "批量分析优化",
                "统一结果格式"
            ],
            "analyzers": {
                ext: analyzer.get_analyzer_info()
                for ext, analyzer in self.analyzer_mapping.items()
            }
        }

    def _get_language_name(self, extension: str) -> str:
        """根据文件扩展名获取语言名称"""
        language_map = {
            '.py': 'Python',
            '.pyw': 'Python',
            '.pyi': 'Python',
            '.js': 'JavaScript',
            '.jsx': 'JavaScript (React)',
            '.mjs': 'JavaScript (ES Module)',
            '.cjs': 'JavaScript (CommonJS)'
        }
        return language_map.get(extension, 'Unknown')

    def get_supported_extensions(self) -> List[str]:
        """获取支持的文件扩展名列表"""
        return self.supported_extensions.copy()

    def is_supported_file(self, file_path: Path) -> bool:
        """检查文件是否支持分析"""
        return file_path.suffix.lower() in self.supported_extensions

    def get_analyzer_for_file(self, file_path: Path) -> Optional[ICodeAnalyzer]:
        """获取指定文件的分析器"""
        extension = file_path.suffix.lower()
        return self.analyzer_mapping.get(extension)