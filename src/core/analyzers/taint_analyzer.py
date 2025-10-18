#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
污点分析器
实现数据流分析,追踪不安全数据从输入源到危险函数的全过程
"""

import ast
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class TaintType(Enum):
    """污点类型枚举"""

    USER_INPUT = "user_input"  # 用户输入
    REQUEST_PARAM = "request_param"  # 请求参数
    FILE_INPUT = "file_input"  # 文件输入
    ENVIRONMENT = "environment"  # 环境变量
    DATABASE = "database"  # 数据库输入
    NETWORK = "network"  # 网络输入


class TaintStatus(Enum):
    """污点状态枚举"""

    TAINTED = "tainted"  # 已污染
    CLEAN = "clean"  # 干净
    UNKNOWN = "unknown"  # 未知


@dataclass
class TaintSource:
    """污点源"""

    name: str  # 变量名
    taint_type: TaintType  # 污点类型
    line: int  # 行号
    source_function: str  # 源函数
    confidence: float = 1.0  # 置信度


@dataclass
class TaintFlow:
    """污点滴流"""

    source: TaintSource  # 污点源
    sink: str  # 污染点（危险函数）
    sink_line: int  # 污染点行号
    flow_path: List[str]  # 数据流路径
    confidence: float = 1.0  # 置信度


@dataclass
class SanitizerInfo:
    """清理函数信息"""

    function_name: str  # 函数名
    effectiveness: float  # 有效性（0-1）
    taint_types: Set[TaintType]  # 可处理的污点类型


class TaintAnalyzer:
    """污点分析器"""

    def __init__(self):
        self.taint_sources: Dict[str, TaintSource] = {}
        self.taint_flows: List[TaintFlow] = []
        self.sanitizers = self._init_sanitizers()
        self.dangerous_functions = self._init_dangerous_functions()
        self.user_input_functions = self._init_user_input_functions()

    def _init_sanitizers(self) -> Dict[str, SanitizerInfo]:
        """初始化清理函数库"""
        return {
            # SQL注入清理
            "escape_sql": SanitizerInfo("escape_sql", 0.9, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}),
            "quote": SanitizerInfo("quote", 0.8, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}),
            "mysql_real_escape_string": SanitizerInfo("mysql_real_escape_string", 0.9, {TaintType.USER_INPUT}),
            # XSS清理
            "escape_html": SanitizerInfo("escape_html", 0.95, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}),
            "htmlspecialchars": SanitizerInfo(
                "htmlspecialchars", 0.95, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}
            ),
            "bleach.clean": SanitizerInfo("bleach.clean", 0.9, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}),
            # 命令注入清理
            "escape_shell_arg": SanitizerInfo(
                "escape_shell_arg", 0.95, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}
            ),
            "escapeshellarg": SanitizerInfo("escapeshellarg", 0.95, {TaintType.USER_INPUT, TaintType.REQUEST_PARAM}),
            # 路径清理
            "basename": SanitizerInfo("basename", 0.8, {TaintType.USER_INPUT, TaintType.FILE_INPUT}),
            "realpath": SanitizerInfo("realpath", 0.7, {TaintType.USER_INPUT, TaintType.FILE_INPUT}),
            "path.normpath": SanitizerInfo("path.normpath", 0.6, {TaintType.USER_INPUT, TaintType.FILE_INPUT}),
        }

    def _init_dangerous_functions(self) -> Dict[str, List[TaintType]]:
        """初始化危险函数库"""
        return {
            # SQL注入相关
            "execute": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "executemany": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "cursor.execute": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "query": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "raw": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            # 命令注入相关
            "os.system": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "subprocess.call": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "subprocess.run": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "subprocess.Popen": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "popen": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "spawn": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            # XSS相关
            "innerHTML": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "document.write": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "eval": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "Function": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "render_template_string": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            "mark_safe": [TaintType.USER_INPUT, TaintType.REQUEST_PARAM],
            # 反序列化相关
            "pickle.loads": [TaintType.USER_INPUT, TaintType.NETWORK, TaintType.FILE_INPUT],
            "pickle.load": [TaintType.USER_INPUT, TaintType.NETWORK, TaintType.FILE_INPUT],
            "yaml.load": [TaintType.USER_INPUT, TaintType.NETWORK, TaintType.FILE_INPUT],
            "exec": [TaintType.USER_INPUT, TaintType.NETWORK, TaintType.FILE_INPUT],
            # 文件操作相关
            "open": [TaintType.USER_INPUT, TaintType.FILE_INPUT],
            "file": [TaintType.USER_INPUT, TaintType.FILE_INPUT],
        }

    def _init_user_input_functions(self) -> Dict[str, TaintType]:
        """初始化用户输入函数库"""
        return {
            # Web框架输入
            "request.args.get": TaintType.REQUEST_PARAM,
            "request.form.get": TaintType.REQUEST_PARAM,
            "request.json.get": TaintType.REQUEST_PARAM,
            "request.data": TaintType.REQUEST_PARAM,
            "request.values.get": TaintType.REQUEST_PARAM,
            "request.cookies.get": TaintType.REQUEST_PARAM,
            "request.headers.get": TaintType.REQUEST_PARAM,
            "request.files.get": TaintType.FILE_INPUT,
            # 标准输入
            "input": TaintType.USER_INPUT,
            "raw_input": TaintType.USER_INPUT,
            "sys.stdin.read": TaintType.USER_INPUT,
            "sys.stdin.readline": TaintType.USER_INPUT,
            # 环境变量
            "os.environ.get": TaintType.ENVIRONMENT,
            "os.getenv": TaintType.ENVIRONMENT,
            # 文件读取
            "open": TaintType.FILE_INPUT,
            "file.read": TaintType.FILE_INPUT,
            "read": TaintType.FILE_INPUT,
            "readlines": TaintType.FILE_INPUT,
            "csv.reader": TaintType.FILE_INPUT,
            "json.load": TaintType.FILE_INPUT,
            # 网络输入
            "socket.recv": TaintType.NETWORK,
            "urllib.request.urlopen": TaintType.NETWORK,
            "requests.get": TaintType.NETWORK,
            "requests.post": TaintType.NETWORK,
        }

    def analyze_taint_flows(self, ast_tree: ast.AST, content: str) -> List[TaintFlow]:
        """分析污点数据流"""
        self.taint_sources.clear()
        self.taint_flows.clear()

        # 第一阶段：识别污点源
        self._identify_taint_sources(ast_tree)

        # 第二阶段：追踪数据流
        self._track_data_flow(ast_tree)

        # 第三阶段：识别危险使用
        self._identify_dangerous_usage(ast_tree)

        return self.taint_flows

    def _identify_taint_sources(self, ast_tree: ast.AST):
        """识别污点源"""

        class TaintSourceVisitor(ast.NodeVisitor):
            def __init__(self, analyzer):
                self.analyzer = analyzer

            def visit_Assign(self, node):
                """检查赋值语句中的污点源"""
                self._check_assignment_for_taint_source(node)
                self.generic_visit(node)

            def visit_Call(self, node):
                """检查函数调用中的污点源"""
                self._check_call_for_taint_source(node)
                self.generic_visit(node)

            def _check_assignment_for_taint_source(self, node: ast.Assign):
                """检查赋值语句是否包含污点源"""
                if isinstance(node.value, ast.Call):
                    func_name = self._get_full_name(node.value.func)
                    if func_name in self.analyzer.user_input_functions:
                        taint_type = self.analyzer.user_input_functions[func_name]

                        # 获取目标变量名
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                taint_source = TaintSource(
                                    name=target.id,
                                    taint_type=taint_type,
                                    line=node.lineno,
                                    source_function=func_name,
                                    confidence=0.9,
                                )
                                self.analyzer.taint_sources[target.id] = taint_source

            def _check_call_for_taint_source(self, node: ast.Call):
                """检查函数调用是否包含污点源"""
                func_name = self._get_full_name(node.func)
                if func_name in self.analyzer.user_input_functions:
                    # 处理内联函数调用的情况
                    # 这里可以处理更复杂的情况
                    taint_type = self.analyzer.user_input_functions[func_name]
                    # TODO: 实现内联函数调用的污点源处理逻辑
                    pass

            def _get_full_name(self, node: ast.AST) -> str:
                """获取完整的节点名称"""
                if isinstance(node, ast.Name):
                    return node.id
                elif isinstance(node, ast.Attribute):
                    return f"{self._get_full_name(node.value)}.{node.attr}"
                return ""

        visitor = TaintSourceVisitor(self)
        visitor.visit(ast_tree)

    def _track_data_flow(self, ast_tree: ast.AST):
        """追踪数据流"""

        class DataFlowVisitor(ast.NodeVisitor):
            def __init__(self, analyzer):
                self.analyzer = analyzer
                self.variable_taint_map = {}

            def visit_Assign(self, node):
                """追踪赋值语句中的数据流"""
                self._track_assignment_taint(node)
                self.generic_visit(node)

            def visit_Call(self, node):
                """追踪函数调用中的数据流"""
                self._track_call_taint(node)
                self.generic_visit(node)

            def _track_assignment_taint(self, node: ast.Assign):
                """追踪赋值语句中的污点传播"""
                # 检查右值是否包含污点变量
                tainted_vars = self._extract_tainted_variables(node.value)

                if tainted_vars:
                    # 左值变量也被污染
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.variable_taint_map[target.id] = tainted_vars

            def _track_call_taint(self, node: ast.Call):
                """追踪函数调用中的污点传播"""
                # 检查参数是否包含污点变量
                for arg in node.args:
                    tainted_vars = self._extract_tainted_variables(arg)
                    if tainted_vars:
                        # 记录函数调用中的污点传播
                        pass

            def _extract_tainted_variables(self, node: ast.AST) -> Set[str]:
                """提取AST节点中的污点变量"""
                tainted_vars = set()

                class VariableExtractor(ast.NodeVisitor):
                    def __init__(self):
                        self.vars = set()

                    def visit_Name(self, node):
                        if isinstance(node.ctx, ast.Load):
                            self.vars.add(node.id)
                        self.generic_visit(node)

                extractor = VariableExtractor()
                extractor.visit(node)

                # 检查提取的变量是否在污点源中
                for var in extractor.vars:
                    if var in self.analyzer.taint_sources:
                        tainted_vars.add(var)

                return tainted_vars

        visitor = DataFlowVisitor(self)
        visitor.visit(ast_tree)

    def _identify_dangerous_usage(self, ast_tree: ast.AST):
        """识别危险使用"""

        class DangerousUsageVisitor(ast.NodeVisitor):
            def __init__(self, analyzer):
                self.analyzer = analyzer

            def visit_Call(self, node):
                """检查危险函数调用"""
                self._check_dangerous_call(node)
                self.generic_visit(node)

            def _check_dangerous_call(self, node: ast.Call):
                """检查危险函数调用"""
                func_name = self._get_full_name(node.func)

                if func_name in self.analyzer.dangerous_functions:
                    # 检查参数是否包含污点变量
                    tainted_args = self._get_tainted_arguments(node)

                    if tainted_args:
                        # 检查是否经过清理函数
                        if not self._has_sanitizer(node):
                            self._create_taint_flow(func_name, node, tainted_args)

            def _get_tainted_arguments(self, node: ast.Call) -> List[Tuple[str, TaintSource]]:
                """获取污点参数"""
                tainted_args = []

                # 检查位置参数
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if arg.id in self.analyzer.taint_sources:
                            tainted_args.append((arg.id, self.analyzer.taint_sources[arg.id]))

                # 检查关键字参数
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name):
                        if kw.value.id in self.analyzer.taint_sources:
                            tainted_args.append((kw.value.id, self.analyzer.taint_sources[kw.value.id]))

                return tainted_args

            def _has_sanitizer(self, node: ast.Call) -> bool:
                """检查是否使用了清理函数"""
                # 简化实现：检查调用链中是否包含清理函数
                # 在实际实现中,需要更复杂的上下文分析
                return False

            def _create_taint_flow(self, func_name: str, node: ast.Call, tainted_args: List[Tuple[str, TaintSource]]):
                """创建污点滴流"""
                for var_name, taint_source in tainted_args:
                    flow = TaintFlow(
                        source=taint_source,
                        sink=func_name,
                        sink_line=node.lineno,
                        flow_path=[var_name, func_name],
                        confidence=self._calculate_flow_confidence(taint_source, func_name),
                    )
                    self.analyzer.taint_flows.append(flow)

            def _calculate_flow_confidence(self, source: TaintSource, sink: str) -> float:
                """计算数据流置信度"""
                # 基于源类型和危险函数类型计算置信度
                base_confidence = source.confidence

                # 根据污点类型和危险函数的匹配度调整
                if sink in self.analyzer.dangerous_functions:
                    expected_taint_types = self.analyzer.dangerous_functions[sink]
                    if source.taint_type in expected_taint_types:
                        base_confidence *= 1.0
                    else:
                        base_confidence *= 0.8

                return min(base_confidence, 1.0)

            def _get_full_name(self, node: ast.AST) -> str:
                """获取完整的节点名称"""
                if isinstance(node, ast.Name):
                    return node.id
                elif isinstance(node, ast.Attribute):
                    return f"{self._get_full_name(node.value)}.{node.attr}"
                return ""

        visitor = DangerousUsageVisitor(self)
        visitor.visit(ast_tree)

    def get_taint_summary(self) -> Dict[str, Any]:
        """获取污点分析摘要"""
        return {
            "taint_sources": len(self.taint_sources),
            "taint_flows": len(self.taint_flows),
            "sources_by_type": self._count_sources_by_type(),
            "flows_by_sink": self._count_flows_by_sink(),
            "high_confidence_flows": len([f for f in self.taint_flows if f.confidence > 0.8]),
        }

    def _count_sources_by_type(self) -> Dict[str, int]:
        """按类型统计污点源"""
        counts = {}
        for source in self.taint_sources.values():
            taint_type = source.taint_type.value
            counts[taint_type] = counts.get(taint_type, 0) + 1
        return counts

    def _count_flows_by_sink(self) -> Dict[str, int]:
        """按污染点统计污点滴流"""
        counts = {}
        for flow in self.taint_flows:
            sink = flow.sink
            counts[sink] = counts.get(sink, 0) + 1
        return counts

    def is_variable_tainted(self, var_name: str) -> bool:
        """检查变量是否被污染"""
        return var_name in self.taint_sources

    def get_variable_taint_source(self, var_name: str) -> Optional[TaintSource]:
        """获取变量的污点源信息"""
        return self.taint_sources.get(var_name)

    def get_taint_flows_for_sink(self, sink_function: str) -> List[TaintFlow]:
        """获取特定污染点的污点滴流"""
        return [flow for flow in self.taint_flows if flow.sink == sink_function]
