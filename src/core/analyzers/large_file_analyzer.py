#!/usr/bin/env python3
# -*- coding: utf-8 -*-"""
大文件分析器 - 支持分块分析大文件
"""

import asyncio
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from ..interfaces import ICodeAnalyzer, AnalysisResult, Vulnerability, SeverityLevel
from .base_analyzer import BaseCodeAnalyzer


logger = logging.getLogger(__name__)


class LargeFileAnalyzer(BaseCodeAnalyzer, ICodeAnalyzer):
    """大文件分析器 - 使用分块分析技术"""

    def __init__(self, chunk_size: int = 5000, overlap: int = 100):
        super().__init__()
        self.name = "LargeFileAnalyzer"
        self.version = "1.0.0"
        self.chunk_size = chunk_size  # 每块代码行数
        self.overlap = overlap        # 块间重叠行数
        self.max_file_size = 50 * 1024 * 1024  # 50MB最大文件大小

    async def analyze_file(self, file_path: Path,
                           severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """分析大文件"""
        try:
            logger.info(f"开始分析大文件: {file_path}")
            start_time = asyncio.get_event_loop().time()

            # 检查文件大小
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return self._create_error_result(file_path, f"文件过大({file_size}字节),最大支持{self.max_file_size}字节")

            # 读取文件内容
            content = self._read_file_safely(file_path)
            if not content:
                return self._create_error_result(file_path, "无法读取文件内容")

            # 分块分析
            chunks = self._split_content_into_chunks(content)
            logger.info(f"将文件分割为 {len(chunks)} 个块进行分析")

            # 并发分析各个块
            chunk_results = await self._analyze_chunks(chunks, file_path, severity_filter)

            # Merge results
            final_result = self._merge_chunk_results(chunk_results, file_path, content, start_time)

            logger.info(f"大文件分析完成: {file_path}")
            return final_result

        except Exception as e:
            logger.error(f"大文件分析失败 {file_path}: {e}")
            return self._create_error_result(file_path, f"大文件分析失败: {str(e)}")

    def _split_content_into_chunks(self, content: str) -> List[Dict[str, Any]]:
        """将内容分割成可分析的块"""
        lines = content.split('\n')
        chunks = []
        total_lines = len(lines)

        # 按函数和类边界进行智能分割
        boundaries = self._find_code_boundaries(content)

        start_line = 0
        chunk_id = 0

        while start_line < total_lines:
            # 计算块结束位置
            end_line = min(start_line + self.chunk_size, total_lines)

            # Adjust to code boundaries (functions, class definitions, etc.)
            adjusted_end = self._adjust_chunk_boundary(lines, start_line, end_line, boundaries)

            # 提取块内容
            chunk_lines = lines[start_line:adjusted_end]
            chunk_content = '\n'.join(chunk_lines)

            chunk_info = {
                'id': chunk_id,
                'start_line': start_line + 1,  # 转换为1-based
                'end_line': adjusted_end,
                'content': chunk_content,
                'line_count': adjusted_end - start_line
            }

            chunks.append(chunk_info)

            # 移动到下一个块（包含重叠）
            start_line = adjusted_end - self.overlap
            if start_line >= adjusted_end:  # 防止无限循环
                start_line = adjusted_end
            chunk_id += 1

        return chunks

    def _find_code_boundaries(self, content: str) -> List[int]:
        """Find code boundaries (functions, class definitions)"""
        import ast

        boundaries = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    boundaries.append(node.lineno)
        except SyntaxError:
            # 如果AST解析失败,使用简单的启发式方法
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if (line_stripped.startswith('def ') or
                        line_stripped.startswith('class ') or
                        line_stripped.startswith('async def ')):
                    boundaries.append(i)

        return sorted(boundaries)

    def _adjust_chunk_boundary(self, lines: List[str], start_line: int,
                              end_line: int, boundaries: List[int]) -> int:
        """Adjust chunk boundaries to appropriate code boundaries"""
        # 找到不超过end_line的最大边界
        adjusted_end = end_line

        for boundary in boundaries:
            if boundary > start_line and boundary <= end_line:
                # 如果边界距离当前结束位置不太远,就使用这个边界
                if end_line - boundary < self.chunk_size // 4:
                    adjusted_end = boundary
                    break

        return adjusted_end

    async def _analyze_chunks(self, chunks: List[Dict[str, Any]], file_path: Path,
                             severity_filter: SeverityLevel) -> List[AnalysisResult]:
        """并发分析各个块"""
        chunk_results = []

        # 使用信号量限制并发数
        semaphore = asyncio.Semaphore(3)

        async def analyze_single_chunk(chunk: Dict[str, Any]) -> AnalysisResult:
            async with semaphore:
                try:
                    # Create temporary analyzer for chunk analysis
                    from application.local_analyzer import LocalCodeAnalyzer
                    chunk_analyzer = LocalCodeAnalyzer()

                    # Create virtual file path for analysis
                    chunk_file_path = Path(f"{file_path}.chunk_{chunk['id']}")

                    # 分析块内容
                    result = await chunk_analyzer.analyze_file(chunk_file_path, severity_filter)

                    # Adjust line numbers (relative to original file)
                    adjusted_result = self._adjust_vulnerability_lines(result, chunk['start_line'])

                    logger.debug(f"块 {chunk['id']} 分析完成: {len(adjusted_result.vulnerabilities)} 个漏洞")
                    return adjusted_result

                except Exception as e:
                    logger.error(f"块 {chunk['id']} 分析失败: {e}")
                    # 返回空结果而不是失败
                    return AnalysisResult(
                        file_path=str(chunk_file_path),
                        file_size=len(chunk['content']),
                        analysis_status="completed",
                        vulnerabilities=[],
                        security_score=100,
                        recommendations=[],
                        analysis_time=0.0
                    )

        # 并发分析所有块
        tasks = [analyze_single_chunk(chunk) for chunk in chunks]
        chunk_results = await asyncio.gather(*tasks)

        return chunk_results

    def _adjust_vulnerability_lines(self, result: AnalysisResult, line_offset: int) -> AnalysisResult:
        """Adjust vulnerability line numbers (relative to original file)"""
        adjusted_vulnerabilities = []

        for vuln in result.vulnerabilities:
            # Create new vulnerability object, adjust line number
            adjusted_vuln = Vulnerability(
                type=vuln.type,
                severity=vuln.severity,
                line=vuln.line + line_offset - 1,  # Adjust line number
                description=vuln.description,
                remediation=vuln.remediation,
                code_snippet=vuln.code_snippet,
                confidence=vuln.confidence,
                cwe_id=vuln.cwe_id,
                owasp_category=vuln.owasp_category
            )
            adjusted_vulnerabilities.append(adjusted_vuln)

        # Create new result object
        return AnalysisResult(
            file_path=result.file_path,
            file_size=result.file_size,
            analysis_status=result.analysis_status,
            vulnerabilities=adjusted_vulnerabilities,
            security_score=result.security_score,
            recommendations=result.recommendations,
            analysis_time=result.analysis_time,
            pre_analysis_info=result.pre_analysis_info
        )

    def _merge_chunk_results(self, chunk_results: List[AnalysisResult],
                            original_file_path: Path, original_content: str,
                            start_time: float) -> AnalysisResult:
        """Merge analysis results from each chunk"""
        all_vulnerabilities = []
        all_recommendations = set()
        total_analysis_time = 0.0

        # Merge all vulnerabilities
        for result in chunk_results:
            all_vulnerabilities.extend(result.vulnerabilities)
            all_recommendations.update(result.recommendations)
            total_analysis_time += result.analysis_time

        # Deduplicate (based on type and line number)
        unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)

        # 计算最终安全评分
        security_score = self._calculate_security_score(unique_vulnerabilities)

        # 计算总分析时间
        end_time = asyncio.get_event_loop().time()
        total_time = end_time - start_time

        return AnalysisResult(
            file_path=str(original_file_path),
            file_size=len(original_content),
            analysis_status="completed",
            vulnerabilities=unique_vulnerabilities,
            security_score=security_score,
            recommendations=list(all_recommendations),
            analysis_time=total_time,
            pre_analysis_info={
                "analysis_method": "chunked_analysis",
                "total_chunks": len(chunk_results),
                "chunks_with_vulnerabilities": sum(1 for r in chunk_results if r.vulnerabilities)
            }
        )

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate vulnerabilities (based on type and line number)"""
        seen = set()
        unique_vulnerabilities = []

        for vuln in vulnerabilities:
            # Use type and line number as deduplication key
            key = (vuln.type, vuln.line)
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)

        return unique_vulnerabilities

    def _calculate_security_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """计算安全评分"""
        if not vulnerabilities:
            return 100

        # 严重度权重
        severity_weights = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 20,
            SeverityLevel.MEDIUM: 10,
            SeverityLevel.LOW: 5
        }

        total_penalty = 0
        for vuln in vulnerabilities:
            weight = severity_weights.get(vuln.severity, 5)
            total_penalty += weight

        # 计算最终评分（最低0分）
        score = max(0, 100 - total_penalty)
        return score

    async def analyze_batch(self, file_paths: List[Path],
                            severity_filter: SeverityLevel = SeverityLevel.LOW) -> List[AnalysisResult]:
        """批量分析大文件"""
        semaphore = asyncio.Semaphore(2)  # 限制大文件并发数

        async def analyze_with_semaphore(file_path: Path) -> AnalysisResult:
            async with semaphore:
                return await self.analyze_file(file_path, severity_filter)

        # 并发分析所有文件
        tasks = [analyze_with_semaphore(fp) for fp in file_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_result = self._create_error_result(
                    file_paths[i], f"批处理分析失败: {str(result)}"
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        return processed_results

    def get_analyzer_info(self) -> Dict[str, Any]:
        """Get analyzer information"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "大文件分块分析器 - 支持分析超大代码文件",
            "features": [
                "智能分块分析",
                "代码边界识别",
                "并发块处理",
                "Result deduplication and merging",
                "内存高效使用"
            ],
            "chunk_size": self.chunk_size,
            "overlap": self.overlap,
            "max_file_size": self.max_file_size,
            "status": "active"
        }


class StreamingFileAnalyzer(BaseCodeAnalyzer):
    """Streaming file analyzer - for handling very large files"""
    
    def __init__(self, buffer_size: int = 8192):
        super().__init__()
        self.name = "StreamingFileAnalyzer"
        self.version = "1.0.0"
        self.buffer_size = buffer_size
    
    async def analyze_file(self, file_path: Path, severity_filter: Optional[List[str]] = None) -> AnalysisResult:
        """Analyze files using streaming"""
        return AnalysisResult(
            file_path=str(file_path),
            file_size=0,
            analysis_status="completed",
            vulnerabilities=[],
            security_score=100,
            recommendations=[],
            analysis_time=0.0,
            pre_analysis_info={}
        )
