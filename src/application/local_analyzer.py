#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
改进版本地代码分析器
使用AST抽象语法树分析和污点分析, 提高检测准确性
"""

import ast
import re
import logging
from pathlib import Path
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor
import asyncio

from ..core.interfaces import ICodeAnalyzer, AnalysisResult, Vulnerability, SeverityLevel
from ..core.analyzers.base_analyzer import BaseCodeAnalyzer
from ..core.analyzers.taint_analyzer import TaintAnalyzer


logger = logging.getLogger(__name__)


class LocalCodeAnalyzer(BaseCodeAnalyzer, ICodeAnalyzer):
    """改进版本地代码分析器 - 基于AST分析"""

    def __init__(self, concurrent_limit: int = 5):
        super().__init__()
        self.name = "LocalCodeAnalyzer"
        self.version = "2.1.0"  # 版本升级，集成污点分析
        self.concurrent_limit = concurrent_limit
        self.executor = ThreadPoolExecutor(max_workers=concurrent_limit)

        # 初始化污点分析器
        self.taint_analyzer = TaintAnalyzer()

        # 初始化漏洞检测器（注入污点分析器）
        self.detectors = [
            SQLInjectionDetector(self.taint_analyzer),
            CommandInjectionDetector(self.taint_analyzer),
            WeakCryptoDetector(),
            InsecureRandomDetector(),
            HardcodedSecretsDetector(),
            XSSVulnerabilityDetector(self.taint_analyzer),
            InsecureDeserializationDetector(self.taint_analyzer),
            PathTraversalDetector(self.taint_analyzer),
            DebugInfoLeakDetector(),
        ]

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """分析单个文件"""
        try:
            # 读取文件内容
            content = self._read_file_safely(file_path)
            if not content:
                return self._create_error_result(file_path, "无法读取文件内容")

            # 预分析
            start_time = asyncio.get_event_loop().time()
            pre_analysis = self._pre_analyze_content(content)

            # AST分析
            ast_analysis = self._analyze_ast_detailed(content)

            # 漏洞检测
            vulnerabilities = await self._detect_vulnerabilities(
                content, file_path, pre_analysis, ast_analysis, severity_filter
            )

            # 计算安全评分
            security_score = self._calculate_security_score(vulnerabilities)

            # 生成推荐建议
            recommendations = self._generate_recommendations(vulnerabilities)

            # 计算分析时间
            end_time = asyncio.get_event_loop().time()
            analysis_time = end_time - start_time

            return AnalysisResult(
                file_path=str(file_path),
                file_size=len(content),
                analysis_status="completed",
                vulnerabilities=vulnerabilities,
                security_score=security_score,
                recommendations=recommendations,
                analysis_time=analysis_time,
                pre_analysis_info={**pre_analysis, "ast_analysis": ast_analysis},
            )

        except Exception as e:
            logger.error(f"本地分析文件失败 {file_path}: {e}.")
            return self._create_error_result(file_path, f"本地分析失败: {str(e)}.")

    async def analyze_batch(
        self, file_paths: List[Path], severity_filter: SeverityLevel = SeverityLevel.LOW
    ) -> List[AnalysisResult]:
        """批量分析文件"""
        semaphore = asyncio.Semaphore(self.concurrent_limit)

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
                error_result = self._create_error_result(file_paths[i], f"批处理分析失败: {str(result)}.")
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        return processed_results

    def _analyze_ast_detailed(self, content: str) -> Dict[str, Any]:
        """详细的AST分析，集成污点分析"""
        try:
            tree = ast.parse(content)
            ast_info = self._extract_ast_info(tree)

            # 集成污点分析
            taint_flows = self.taint_analyzer.analyze_taint_flows(tree, content)
            ast_info["taint_analysis"] = {
                "taint_flows": taint_flows,
                "taint_summary": self.taint_analyzer.get_taint_summary(),
            }

            return ast_info
        except Exception as e:
            logger.warning(f"AST分析失败: {e}")
            return {}

    def _extract_ast_info(self, tree: ast.AST) -> Dict[str, Any]:
        """提取AST信息"""
        ast_info = {
            "functions": [],
            "classes": [],
            "imports": [],
            "calls": [],
            "strings": [],
            "assignments": [],
            "control_flow": [],
            "potential_dangerous_nodes": [],
        }

        class EnhancedASTVisitor(ast.NodeVisitor):
            def __init__(self):
                self.functions = []
                self.classes = []
                self.imports = []
                self.calls = []
                self.strings = []
                self.assignments = []
                self.control_flow = []
                self.dangerous_nodes = []

            def visit_FunctionDef(self, node):
                func_info = {
                    "name": node.name,
                    "line": node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "defaults": len(node.args.defaults),
                    "decorators": [self._get_full_name(d) for d in node.decorator_list],
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                    "docstring": ast.get_docstring(node),
                }
                self.functions.append(func_info)
                self.generic_visit(node)

            def visit_ClassDef(self, node):
                class_info = {
                    "name": node.name,
                    "line": node.lineno,
                    "bases": [self._get_full_name(base) for base in node.bases],
                    "methods": [],
                }
                # 收集类方法
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        class_info["methods"].append(item.name)
                self.classes.append(class_info)
                self.generic_visit(node)

            def visit_Import(self, node):
                for alias in node.names:
                    self.imports.append(
                        {"name": alias.name, "asname": alias.asname, "line": node.lineno, "type": "import"}
                    )
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                module = node.module or ""
                for alias in node.names:
                    self.imports.append(
                        {
                            "module": module,
                            "name": alias.name,
                            "asname": alias.asname,
                            "line": node.lineno,
                            "type": "from_import",
                        }
                    )
                self.generic_visit(node)

            def visit_Call(self, node):
                func_name = self._get_full_name(node.func)
                if func_name:
                    call_info = {
                        "function": func_name,
                        "line": node.lineno,
                        "args": [self._get_node_type(arg) for arg in node.args],
                        "keywords": [kw.arg for kw in node.keywords if kw.arg],
                    }
                    self.calls.append(call_info)

                    # 检测危险函数调用
                    if self._is_dangerous_function(func_name):
                        self.dangerous_nodes.append(
                            {
                                "type": "dangerous_call",
                                "function": func_name,
                                "line": node.lineno,
                                "risk_level": self._get_function_risk_level(func_name),
                            }
                        )
                self.generic_visit(node)

            def visit_Str(self, node):
                if isinstance(node.s, str):
                    string_info = {"value": node.s[:200], "line": node.lineno, "length": len(node.s)}  # 限制长度
                    self.strings.append(string_info)

                    # 检测硬编码敏感信息
                    if self._contains_sensitive_pattern(node.s):
                        self.dangerous_nodes.append(
                            {
                                "type": "sensitive_string",
                                "line": node.lineno,
                                "pattern": self._get_sensitive_pattern(node.s),
                            }
                        )
                self.generic_visit(node)

            def visit_Constant(self, node):
                if isinstance(node.value, str):
                    string_info = {"value": node.value[:200], "line": node.lineno, "length": len(node.value)}
                    self.strings.append(string_info)

                    if self._contains_sensitive_pattern(node.value):
                        self.dangerous_nodes.append(
                            {
                                "type": "sensitive_string",
                                "line": node.lineno,
                                "pattern": self._get_sensitive_pattern(node.value),
                            }
                        )
                self.generic_visit(node)

            def visit_Assign(self, node):
                for target in node.targets:
                    target_name = self._get_full_name(target)
                    if target_name:
                        self.assignments.append(
                            {"target": target_name, "line": node.lineno, "value_type": self._get_node_type(node.value)}
                        )
                self.generic_visit(node)

            def visit_If(self, node):
                self.control_flow.append({"type": "if", "line": node.lineno, "has_else": len(node.orelse) > 0})
                self.generic_visit(node)

            def visit_For(self, node):
                self.control_flow.append({"type": "for", "line": node.lineno})
                self.generic_visit(node)

            def visit_While(self, node):
                self.control_flow.append({"type": "while", "line": node.lineno})
                self.generic_visit(node)

            def visit_ExceptHandler(self, node):
                self.control_flow.append(
                    {
                        "type": "except",
                        "line": node.lineno,
                        "type_annotation": self._get_full_name(node.type) if node.type else None,
                    }
                )
                self.generic_visit(node)

            def _get_full_name(self, node):
                """获取完整的节点名称"""
                if isinstance(node, ast.Name):
                    return node.id
                elif isinstance(node, ast.Attribute):
                    return f"{self._get_full_name(node.value)}.{node.attr}"
                return None

            def _get_node_type(self, node):
                """获取节点类型"""
                if isinstance(node, ast.Str):
                    return "string"
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    return "string"
                elif isinstance(node, ast.Num):
                    return "number"
                elif isinstance(node, ast.Name):
                    return "variable"
                elif isinstance(node, ast.Call):
                    return "function_call"
                else:
                    return "other"

            def _is_dangerous_function(self, func_name: str) -> bool:
                """检查是否为危险函数"""
                dangerous_functions = [
                    "eval",
                    "exec",
                    "compile",
                    "__import__",
                    "os.system",
                    "subprocess.call",
                    "subprocess.run",
                    "pickle.loads",
                    "pickle.load",
                    "yaml.load",
                    "hashlib.md5",
                    "hashlib.sha1",
                    "random.random",
                    "random.randint",
                ]
                return any(dangerous in func_name for dangerous in dangerous_functions)

            def _get_function_risk_level(self, func_name: str) -> str:
                """获取函数风险等级"""
                high_risk = ["eval", "exec", "os.system", "pickle.loads"]
                medium_risk = ["subprocess.call", "hashlib.md5", "random.random"]

                if any(risk in func_name for risk in high_risk):
                    return "high"
                elif any(risk in func_name for risk in medium_risk):
                    return "medium"
                else:
                    return "low"

            def _contains_sensitive_pattern(self, text: str) -> bool:
                """检查是否包含敏感模式"""
                sensitive_patterns = [
                    r"api[_-]?key",
                    r"password",
                    r"secret",
                    r"token",
                    r"-----BEGIN.*KEY-----",
                    r"[A-Za-z0-9]{20,}",  # 长随机字符串可能是密钥
                ]
                return any(re.search(pattern, text, re.IGNORECASE) for pattern in sensitive_patterns)

            def _get_sensitive_pattern(self, text: str) -> str:
                """获取匹配的敏感模式"""
                sensitive_patterns = [
                    ("api_key", r"api[_-]?key"),
                    ("password", r"password"),
                    ("secret", r"secret"),
                    ("token", r"token"),
                    ("private_key", r"-----BEGIN.*KEY-----"),
                    ("random_string", r"[A-Za-z0-9]{20,}"),
                ]

                for pattern_name, pattern in sensitive_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        return pattern_name
                return "unknown"

        visitor = EnhancedASTVisitor()
        visitor.visit(tree)

        ast_info["functions"] = visitor.functions
        ast_info["classes"] = visitor.classes
        ast_info["imports"] = visitor.imports
        ast_info["calls"] = visitor.calls
        ast_info["strings"] = visitor.strings
        ast_info["assignments"] = visitor.assignments
        ast_info["control_flow"] = visitor.control_flow
        ast_info["potential_dangerous_nodes"] = visitor.dangerous_nodes

        return ast_info

    async def _detect_vulnerabilities(
        self,
        content: str,
        file_path: Path,
        pre_analysis: Dict[str, Any],
        ast_analysis: Dict[str, Any],
        severity_filter: SeverityLevel,
    ) -> List[Vulnerability]:
        """检测漏洞"""
        all_vulnerabilities = []

        # 使用多个检测器并发检测
        detection_tasks = []
        for detector in self.detectors:
            task = self._run_detector(detector, content, file_path, pre_analysis, ast_analysis)
            detection_tasks.append(task)

        # 等待所有检测完成
        results = await asyncio.gather(*detection_tasks, return_exceptions=True)

        # 合并结果
        for result in results:
            if isinstance(result, list):
                all_vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.warning(f"检测器运行失败: {result}")

        # 按严重度过滤
        filtered_vulnerabilities = [
            vuln for vuln in all_vulnerabilities if self._should_include_by_severity(vuln.severity, severity_filter)
        ]

        # 去重（基于类型和行号）
        unique_vulnerabilities = self._deduplicate_vulnerabilities(filtered_vulnerabilities)

        return unique_vulnerabilities

    def _should_include_by_severity(
        self, vulnerability_severity: SeverityLevel, filter_severity: SeverityLevel
    ) -> bool:
        """根据严重度判断是否应该包含该漏洞"""
        severity_order = {
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }
        return severity_order.get(vulnerability_severity, 1) >= severity_order.get(filter_severity, 1)

    async def _run_detector(
        self, detector, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """运行单个检测器"""
        try:
            # 在executor中运行检测器（防止阻塞）
            loop = asyncio.get_event_loop()
            vulnerabilities = await loop.run_in_executor(
                self.executor, detector.detect_vulnerabilities, content, file_path, pre_analysis, ast_analysis
            )
            return vulnerabilities
        except Exception as e:
            logger.error(f"检测器 {detector.__class__.__name__} 运行失败: {e}.")
            return []

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """去重漏洞"""
        seen = set()
        unique_vulnerabilities = []

        for vuln in vulnerabilities:
            # 基于类型和行号去重
            key = (vuln.type, vuln.line)
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)

        return unique_vulnerabilities

    def _calculate_security_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """计算安全评分"""
        if not vulnerabilities:
            return 100

        # 严重度权重（考虑置信度）
        severity_weights = {
            SeverityLevel.CRITICAL: 30,
            SeverityLevel.HIGH: 20,
            SeverityLevel.MEDIUM: 10,
            SeverityLevel.LOW: 5,
        }

        total_penalty = 0
        for vuln in vulnerabilities:
            base_weight = severity_weights.get(vuln.severity, 5)
            # 根据置信度调整权重
            adjusted_weight = base_weight * vuln.confidence
            total_penalty += adjusted_weight

        # 计算最终评分（最低0分）
        score = max(0, 100 - int(total_penalty))
        return score

    def _generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """生成安全建议"""
        recommendations = set()

        for vuln in vulnerabilities:
            vuln_type = vuln.type.lower()

            # 根据漏洞类型添加具体建议
            if "sql" in vuln_type:
                recommendations.add("使用参数化查询防止SQL注入")
                recommendations.add("实施输入验证和清理机制")
            elif "command" in vuln_type:
                recommendations.add("避免直接执行用户输入")
                recommendations.add("使用安全的参数化API")
            elif "crypto" in vuln_type or "encryption" in vuln_type:
                recommendations.add("使用强加密算法（SHA-256、AES-256）")
                recommendations.add("定期更新加密库和依赖")
            elif "hardcoded" in vuln_type or "secret" in vuln_type:
                recommendations.add("将敏感信息移至环境变量或配置文件")
                recommendations.add("使用专业的密钥管理服务")
            elif "xss" in vuln_type:
                recommendations.add("对用户输入进行HTML转义")
                recommendations.add("使用安全的模板引擎")
            elif "deserialize" in vuln_type:
                recommendations.add("避免反序列化不可信数据源")
                recommendations.add("使用安全的序列化格式（如JSON）")
            elif "traversal" in vuln_type:
                recommendations.add("验证和清理文件路径")
                recommendations.add("使用白名单机制限制文件访问")

        # 通用建议
        recommendations.add("定期更新依赖库到最新版本")
        recommendations.add("实施代码审查流程")
        recommendations.add("使用自动化安全测试工具")
        recommendations.add("对开发团队进行安全培训")

        return list(recommendations)

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "基于AST的本地代码安全分析器",
            "features": [
                "抽象语法树(AST)分析",
                "多检测器并发执行",
                "高精度漏洞识别",
                "低误报率",
                "无需外部依赖",
                "支持大文件分析",
            ],
            "detectors": [detector.__class__.__name__ for detector in self.detectors],
            "concurrent_limit": self.concurrent_limit,
            "status": "active",
        }


# 具体的漏洞检测器实现
class SQLInjectionDetector:
    """SQL注入检测器 - 基于AST和污点分析的联合分析"""

    def __init__(self, taint_analyzer=None):
        """初始化检测器，可选注入污点分析器"""
        self.taint_analyzer = taint_analyzer

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测SQL注入漏洞"""
        vulnerabilities = []

        # 1. 污点分析检测（如果可用）
        if self.taint_analyzer and "taint_analysis" in ast_analysis:
            taint_flows = ast_analysis["taint_analysis"]["taint_flows"]
            sql_injection_flows = [flow for flow in taint_flows if self._is_sql_related_sink(flow.sink)]

            for flow in sql_injection_flows:
                vulnerability = Vulnerability(
                    type="SQL注入(污点分析)",
                    severity=SeverityLevel.HIGH,
                    line=flow.sink_line,
                    description=f"检测到SQL注入数据流: {flow.source.name} -> {flow.sink}, 污点源: {flow.source.source_function}",
                    remediation="使用参数化查询，避免将用户输入直接拼接到SQL语句中",
                    code_snippet=f"{flow.source.name} -> {flow.sink}",
                    confidence=flow.confidence,
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection",
                )
                vulnerabilities.append(vulnerability)

        # 2. 传统的AST分析检测
        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            # 检查数据库相关函数
            if self._is_database_function(func_name):
                if self._has_sql_injection_pattern(call_info, ast_analysis):
                    vulnerability = Vulnerability(
                        type="SQL注入",
                        severity=SeverityLevel.HIGH,
                        line=line,
                        description=f"检测到潜在的SQL注入风险: {func_name} 使用不安全的参数构造.",
                        remediation="使用参数化查询或ORM的安全方法，避免字符串拼接构造SQL语句",
                        code_snippet=func_name,
                        confidence=0.85,
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 – Injection",
                    )
                    vulnerabilities.append(vulnerability)

        # 使用正则表达式作为补充检测
        supplementary_vulns = self._regex_based_detection(content)
        vulnerabilities.extend(supplementary_vulns)

        return vulnerabilities

    def _is_sql_related_sink(self, sink_function: str) -> bool:
        """检查是否为SQL相关的污染点"""
        sql_related_functions = [
            "execute",
            "executemany",
            "executescript",
            "cursor.execute",
            "cursor.executemany",
            "query",
            "select",
            "insert",
            "update",
            "delete",
            "raw",
            "extra",
            "annotate",
            "filter",
            "get",
        ]
        return any(sql_func in sink_function.lower() for sql_func in sql_related_functions)

    def _is_database_function(self, func_name: str) -> bool:
        """检查是否为数据库相关函数"""
        db_functions = [
            "execute",
            "executemany",
            "executescript",
            "cursor.execute",
            "cursor.executemany",
            "query",
            "select",
            "insert",
            "update",
            "delete",
            "raw",
            "extra",
            "annotate",
        ]
        return any(db_func in func_name.lower() for db_func in db_functions)

    def _has_sql_injection_pattern(self, call_info: Dict[str, Any], ast_analysis: Dict[str, Any]) -> bool:
        """检查是否存在SQL注入模式"""
        # 检查参数中是否包含字符串拼接
        args = call_info.get("args", [])

        # 检查参数类型
        for arg in args:
            if arg == "string":  # 字符串字面量
                # 进一步检查是否为SQL语句拼接
                if self._is_sql_concatenation(call_info, ast_analysis):
                    return True

        # 检查变量赋值链
        if self._check_variable_assignment_chain(call_info, ast_analysis):
            return True

        return False

    def _is_sql_concatenation(self, call_info: Dict[str, Any], ast_analysis: Dict[str, Any]) -> bool:
        """检查是否为SQL语句拼接"""
        # 检查赋值语句中是否有SQL关键字和拼接操作
        for assign_info in ast_analysis.get("assignments", []):
            target = assign_info["target"]
            value_type = assign_info.get("value_type", "")

            # 如果赋值目标是SQL语句且包含字符串操作
            if "query" in target.lower() or "sql" in target.lower():
                if value_type in ["string", "function_call"]:
                    return True
        return False

    def _check_variable_assignment_chain(self, call_info: Dict[str, Any], ast_analysis: Dict[str, Any]) -> bool:
        """检查变量赋值链是否存在风险"""
        # 分析变量的来源和赋值历史
        keywords = call_info.get("keywords", [])

        for kw in keywords:
            # 检查参数变量名是否暗示用户输入
            if any(indicator in kw.lower() for indicator in ["user", "input", "param", "data"]):
                return True
        return False

    def _regex_based_detection(self, content: str) -> List[Vulnerability]:
        """基于正则表达式的补充检测"""
        vulnerabilities = []

        dangerous_patterns = [
            (r"execute\s*\([^)]*\+[^)]*\)", "SQL字符串拼接"),
            (r"execute\s*\([^)]*%[^)]*\)", "SQL字符串格式化"),
            (r"execute\s*\([^)]*\.format[^)]*\)", "SQL format方法"),
            (r'query\s*=\s*["\'].*\+.*["\\]', "查询字符串拼接"),
            (r'\.execute\s*\(\s*f[\'"].*{.*}', "f-string SQL拼接"),
        ]

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if line_stripped.startswith("#"):
                continue

            for pattern, description in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerability = Vulnerability(
                        type="SQL注入",
                        severity=SeverityLevel.HIGH,
                        line=i,
                        description=f"检测到{description}, 可能导致SQL注入攻击",
                        remediation="使用参数化查询或ORM的安全方法，避免字符串拼接构造SQL",
                        code_snippet=line.strip()[:150],
                        confidence=0.9,
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 – Injection",
                    )
                    vulnerabilities.append(vulnerability)
                    break

        return vulnerabilities


class CommandInjectionDetector:
    """命令注入检测器 - 基于AST和污点分析的联合分析"""

    def __init__(self, taint_analyzer=None):
        """初始化检测器，可选注入污点分析器"""
        self.taint_analyzer = taint_analyzer

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测命令注入漏洞"""
        vulnerabilities = []

        # 1. 污点分析检测（如果可用）
        if self.taint_analyzer and "taint_analysis" in ast_analysis:
            taint_flows = ast_analysis["taint_analysis"]["taint_flows"]
            command_injection_flows = [flow for flow in taint_flows if self._is_command_related_sink(flow.sink)]

            for flow in command_injection_flows:
                vulnerability = Vulnerability(
                    type="命令注入(污点分析)",
                    severity=SeverityLevel.HIGH,
                    line=flow.sink_line,
                    description=f"检测到命令注入数据流: {flow.source.name} -> {flow.sink}, 污点源: {flow.source.source_function}",
                    remediation="避免直接执行用户输入，使用参数化命令执行或白名单验证",
                    code_snippet=f"{flow.source.name} -> {flow.sink}",
                    confidence=flow.confidence,
                    cwe_id="CWE-78",
                    owasp_category="A03:2021 – Injection",
                )
                vulnerabilities.append(vulnerability)

        # 2. 传统的AST分析检测
        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            if self._is_command_injection_risk(func_name, call_info, ast_analysis):
                vulnerability = Vulnerability(
                    type="命令注入",
                    severity=SeverityLevel.HIGH,
                    line=line,
                    description=f"检测到危险的系统命令调用: {func_name}",
                    remediation="避免直接执行用户输入，使用参数化命令执行或白名单验证",
                    code_snippet=func_name,
                    confidence=0.85,
                    cwe_id="CWE-78",
                    owasp_category="A03:2021 – Injection",
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_command_related_sink(self, sink_function: str) -> bool:
        """检查是否为命令相关的污染点"""
        command_related_functions = [
            "os.system",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "popen",
            "spawn",
            "fork",
            "exec",
            "eval",
            "exec",
            "shell_exec",
        ]
        return any(cmd_func in sink_function for cmd_func in command_related_functions)

    def _is_command_injection_risk(
        self, func_name: str, call_info: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> bool:
        """检查是否存在命令注入风险"""
        dangerous_functions = [
            "os.system",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "popen",
            "spawn",
            "fork",
            "exec",
            "eval",
            "exec",
        ]

        # 检查函数名
        is_dangerous = any(dangerous in func_name for dangerous in dangerous_functions)
        if not is_dangerous:
            return False

        # 检查参数中是否包含用户输入相关的变量
        args = call_info.get("args", [])
        keywords = call_info.get("keywords", [])

        # 检查参数类型和内容
        for arg in args:
            if arg == "string":  # 字符串字面量
                # 检查是否为拼接构造的命令
                if self._is_command_concatenation(call_info, ast_analysis):
                    return True

        # 检查变量赋值链 - 追溯变量来源
        for kw in keywords:
            if self._is_user_input_related(kw, ast_analysis):
                return True

        # 检查函数参数是否来自用户输入
        if self._trace_variable_source(call_info, ast_analysis):
            return True

        return False

    def _is_command_concatenation(self, call_info: Dict[str, Any], ast_analysis: Dict[str, Any]) -> bool:
        """检查是否为命令拼接"""
        # 检查赋值语句中是否有命令构造
        for assign_info in ast_analysis.get("assignments", []):
            target = assign_info["target"]
            value_type = assign_info.get("value_type", "")

            # 如果变量名暗示命令构造
            if any(indicator in target.lower() for indicator in ["cmd", "command", "shell"]):
                if value_type == "string":
                    return True
        return False

    def _is_user_input_related(self, variable_name: str, ast_analysis: Dict[str, Any]) -> bool:
        """检查变量是否与用户输入相关"""
        user_input_indicators = ["user", "input", "request", "param", "data", "form", "get", "post"]

        # 检查变量名
        if any(indicator in variable_name.lower() for indicator in user_input_indicators):
            return True

        # 检查赋值语句中的变量名
        for assign_info in ast_analysis.get("assignments", []):
            target = assign_info["target"]
            if target == variable_name:
                # 检查赋值来源
                if any(indicator in target.lower() for indicator in user_input_indicators):
                    return True

        return False

    def _trace_variable_source(self, call_info: Dict[str, Any], ast_analysis: Dict[str, Any]) -> bool:
        """追溯变量来源"""
        # 简化的变量追溯逻辑
        # 在实际实现中可以构建更复杂的数据流图
        keywords = call_info.get("keywords", [])

        for kw in keywords:
            # 检查变量名是否暗示用户输入
            if any(indicator in kw.lower() for indicator in ["user", "input", "request", "param"]):
                return True

        return False


class WeakCryptoDetector:
    """弱加密算法检测器"""

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测弱加密算法使用"""
        vulnerabilities = []

        weak_algorithms = {
            "hashlib.md5": ("MD5", "使用SHA-256或更强的哈希算法"),
            "hashlib.sha1": ("SHA1", "使用SHA-256或更强的哈希算法"),
            "MD5": ("MD5", "使用SHA-256或更强的哈希算法"),
            "SHA1": ("SHA1", "使用SHA-256或更强的哈希算法"),
            "DES": ("DES", "使用AES-256等现代加密算法"),
            "RC4": ("RC4", "使用AES-256等现代加密算法"),
        }

        # 检查函数调用
        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            for weak_func, (algo_name, suggestion) in weak_algorithms.items():
                if weak_func in func_name:
                    vulnerability = Vulnerability(
                        type="弱加密算法",
                        severity=SeverityLevel.MEDIUM,
                        line=line,
                        description=f"使用已废弃的加密算法: {algo_name}",
                        remediation=suggestion,
                        code_snippet=func_name,
                        confidence=0.95,
                        cwe_id="CWE-327",
                        owasp_category="A02:2021 – Cryptographic Failures",
                    )
                    vulnerabilities.append(vulnerability)
                    break

        return vulnerabilities


class HardcodedSecretsDetector:
    """硬编码敏感信息检测器"""

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测硬编码的敏感信息"""
        vulnerabilities = []

        # 检查字符串常量
        for string_info in ast_analysis.get("strings", []):
            text = string_info["value"]
            line = string_info["line"]

            if self._is_hardcoded_secret(text):
                secret_type = self._get_secret_type(text)
                vulnerability = Vulnerability(
                    type="硬编码敏感信息",
                    severity=SeverityLevel.HIGH,
                    line=line,
                    description=f"检测到硬编码的{secret_type}",
                    remediation="将敏感信息移至环境变量或配置文件，使用密钥管理服务",
                    code_snippet=text[:50] + "..." if len(text) > 50 else text,
                    confidence=0.8,
                    cwe_id="CWE-798",
                    owasp_category="A09:2021 – Security Logging and Monitoring Failures",
                )
                vulnerabilities.append(vulnerability)

        # 检查赋值语句
        for assign_info in ast_analysis.get("assignments", []):
            target = assign_info["target"]
            line = assign_info["line"]

            if self._is_sensitive_variable_name(target):
                vulnerability = Vulnerability(
                    type="硬编码敏感信息",
                    severity=SeverityLevel.MEDIUM,
                    line=line,
                    description=f"变量名'{target}'暗示可能包含敏感信息",
                    remediation="检查该变量是否包含敏感数据，考虑使用环境变量",
                    code_snippet=target,
                    confidence=0.6,
                    cwe_id="CWE-798",
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_hardcoded_secret(self, text: str) -> bool:
        """检查是否为硬编码密钥"""
        secret_patterns = [
            (r"[A-Za-z0-9]{32,}", "长随机字符串"),  # API密钥等
            (r"sk-[A-Za-z0-9]{48}", "OpenAI API密钥"),
            (r"-----BEGIN.*KEY-----", "私钥/证书"),
            (r'(password|passwd|pwd)\s*=\s*["\'][^"\\]{8,}["\\]', "密码"),
            (r'(api[_-]?key|secret|token)\s*=\s*["\'][^"\\]{16,}["\\]', "API密钥"),
        ]

        for pattern, _ in secret_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _get_secret_type(self, text: str) -> str:
        """获取密钥类型"""
        if re.search(r"sk-[A-Za-z0-9]{48}", text):
            return "OpenAI API密钥"
        elif re.search(r"-----BEGIN.*KEY-----", text):
            return "私钥/证书"
        elif re.search(r"(password|passwd|pwd)", text, re.IGNORECASE):
            return "密码"
        elif re.search(r"(api[_-]?key|secret|token)", text, re.IGNORECASE):
            return "API密钥"
        elif len(text) > 30 and re.search(r"[A-Za-z0-9]", text):
            return "长随机字符串（可能是密钥）"
        else:
            return "敏感信息"

    def _is_sensitive_variable_name(self, name: str) -> bool:
        """检查变量名是否敏感"""
        sensitive_names = ["password", "passwd", "pwd", "secret", "key", "token", "api_key"]
        return any(sensitive in name.lower() for sensitive in sensitive_names)


class InsecureDeserializationDetector:
    """不安全反序列化检测器"""

    def __init__(self, taint_analyzer=None):
        """初始化检测器，可选注入污点分析器"""
        self.taint_analyzer = taint_analyzer

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测不安全反序列化"""
        vulnerabilities = []

        # 检查危险函数调用
        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            dangerous_funcs = ["pickle.loads", "pickle.load", "yaml.load", "eval", "exec"]

            for dangerous_func in dangerous_funcs:
                if dangerous_func in func_name:
                    severity = SeverityLevel.HIGH if "pickle" in func_name else SeverityLevel.MEDIUM
                    vulnerability = Vulnerability(
                        type="不安全反序列化",
                        severity=severity,
                        line=line,
                        description=f"检测到不安全的反序列化操作: {func_name}",
                        remediation="避免反序列化不可信数据，使用安全的序列化格式如JSON",
                        code_snippet=func_name,
                        confidence=0.9,
                        cwe_id="CWE-502",
                        owasp_category="A08:2021 – Software and Data Integrity Failures",
                    )
                    vulnerabilities.append(vulnerability)
                    break

        return vulnerabilities


class XSSVulnerabilityDetector:
    """XSS漏洞检测器"""

    def __init__(self, taint_analyzer=None):
        """初始化XSS漏洞检测器"""
        self.taint_analyzer = taint_analyzer

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测XSS漏洞"""
        vulnerabilities = []

        # 检查危险函数调用
        dangerous_funcs = ["render_template_string", "mark_safe", "innerHTML", "document.write", "eval", "Function"]

        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            for dangerous_func in dangerous_funcs:
                if dangerous_func in func_name:
                    vulnerability = Vulnerability(
                        type="XSS漏洞",
                        severity=SeverityLevel.MEDIUM,
                        line=line,
                        description=f"检测到可能的XSS漏洞: {func_name}",
                        remediation="对用户输入进行HTML转义，使用安全的模板引擎",
                        code_snippet=func_name,
                        confidence=0.7,
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 – Injection",
                    )
                    vulnerabilities.append(vulnerability)
                    break

        return vulnerabilities


class InsecureRandomDetector:
    """不安全随机数检测器"""

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测不安全随机数使用"""
        vulnerabilities = []

        # 检查随机数函数调用
        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            if func_name in ["random.random", "random.randint", "random.choice"]:
                vulnerability = Vulnerability(
                    type="不安全随机数",
                    severity=SeverityLevel.MEDIUM,
                    line=line,
                    description=f"使用不安全的随机数生成器: {func_name}",
                    remediation="使用secrets模块生成加密安全的随机数",
                    code_snippet=func_name,
                    confidence=0.8,
                    cwe_id="CWE-330",
                    owasp_category="A02:2021 – Cryptographic Failures",
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities


class PathTraversalDetector:
    """路径遍历检测器"""

    def __init__(self, taint_analyzer=None):
        """初始化检测器，可选注入污点分析器"""
        self.taint_analyzer = taint_analyzer

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测路径遍历漏洞"""
        vulnerabilities = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            # 检查路径遍历模式
            if re.search(r"\.\./|\.\\.\\", line):
                vulnerability = Vulnerability(
                    type="路径遍历",
                    severity=SeverityLevel.LOW,
                    line=i,
                    description="检测到可能的路径遍历序列",
                    remediation="验证和清理文件路径，使用白名单机制",
                    code_snippet=line.strip()[:100],
                    confidence=0.6,
                    cwe_id="CWE-22",
                    owasp_category="A01:2021 – Broken Access Control",
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities


class DebugInfoLeakDetector:
    """调试信息泄露检测器"""

    def detect_vulnerabilities(
        self, content: str, file_path: Path, pre_analysis: Dict[str, Any], ast_analysis: Dict[str, Any]
    ) -> List[Vulnerability]:
        """检测调试信息泄露"""
        vulnerabilities = []

        # 检查print语句和异常处理
        for call_info in ast_analysis.get("calls", []):
            func_name = call_info["function"]
            line = call_info["line"]

            if func_name in ["print", "logging.debug", "logging.info"]:
                vulnerability = Vulnerability(
                    type="调试信息泄露",
                    severity=SeverityLevel.LOW,
                    line=line,
                    description="检测到可能的调试信息输出",
                    remediation="在生产环境中移除调试信息，使用适当的日志级别",
                    code_snippet=func_name,
                    confidence=0.5,
                    cwe_id="CWE-209",
                    owasp_category="A09:2021 – Security Logging and Monitoring Failures",
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities
