#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基础分析器模块
提供通用的分析功能和工具方法
"""

import re
import ast
from pathlib import Path
from typing import Dict, Any, Optional, List
from ..interfaces import AnalysisResult
from .analysis_types import (
    ImportStatement, FunctionDefinition, ClassDefinition, CallExpression,
    StringLiteral, ImportInfo, ComplexityMetrics, ASTInfo, PreAnalysisInfo
)


class BaseCodeAnalyzer:
    """基础代码分析器"""

    def __init__(self) -> None:
        self.name = "BaseCodeAnalyzer"
        self.version = "1.0.0"

    def _read_file_safely(self, file_path: Path) -> Optional[str]:
        """安全读取文件内容"""
        try:
            # Check file size (prevent overly large files)
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB限制
                return None

            # 尝试不同的编码
            for encoding in ["utf-8", "utf-8-sig", "gb2312", "gbk", "latin1"]:
                try:
                    with open(file_path, "r", encoding=encoding) as f:
                        content = f.read()
                        # 验证是否为有效的Python代码
                        if self._validate_python_syntax(content):
                            return content
                except (UnicodeDecodeError, SyntaxError):
                    continue

            return None

        except Exception:
            return None

    def _validate_python_syntax(self, content: str) -> bool:
        """验证Python语法有效性"""
        try:
            compile(content, "<string>", "exec")
            return True
        except SyntaxError:
            return False

    def _pre_analyze_content(self, content: str) -> PreAnalysisInfo:
        """Pre-analyze code content, extract key information"""
        lines = content.split("\n")

        # Initialize data structures
        import_statements: List[ImportStatement] = []
        function_definitions: List[FunctionDefinition] = []
        class_definitions: List[ClassDefinition] = []
        code_lines = 0

        # AST分析
        ast_info: ASTInfo
        try:
            tree = ast.parse(content)
            ast_info = self._analyze_ast(tree)
        except Exception:
            ast_info = ASTInfo([], [], [], [], [], 0)

        # 基本代码统计
        import_pattern = re.compile(r"^(import|from)\s+([\w.]+)")
        function_pattern = re.compile(r"^def\s+(\w+)")
        class_pattern = re.compile(r"^class\s+(\w+)")

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()

            # 跳过空行和注释
            if not line_stripped or line_stripped.startswith("#"):
                continue

            code_lines += 1

            # 检测导入语句
            import_match = import_pattern.match(line_stripped)
            if import_match:
                import_statements.append(
                    ImportStatement(
                        line=i,
                        module=import_match.group(2),
                        full_statement=line_stripped
                    )
                )

            # 检测函数定义
            function_match = function_pattern.match(line_stripped)
            if function_match:
                function_definitions.append(
                    FunctionDefinition(
                        line=i,
                        name=function_match.group(1),
                        full_definition=line_stripped
                    )
                )

            # 检测类定义
            class_match = class_pattern.match(line_stripped)
            if class_match:
                class_definitions.append(
                    ClassDefinition(
                        line=i,
                        name=class_match.group(1),
                        full_definition=line_stripped
                    )
                )

        # 计算复杂度指标
        complexity_metrics = self._calculate_complexity_metrics(content, lines)

        return PreAnalysisInfo(
            total_lines=len(lines),
            code_lines=code_lines,
            import_statements=import_statements,
            function_definitions=function_definitions,
            class_definitions=class_definitions,
            potential_risk_patterns=[],
            complexity_metrics=complexity_metrics,
            ast_info=ast_info
        )

    def _analyze_ast(self, tree: ast.AST) -> ASTInfo:
        """AST分析"""

        class ASTVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.functions: List[FunctionDefinition] = []
                self.classes: List[ClassDefinition] = []
                self.imports: List[ImportInfo] = []
                self.calls: List[CallExpression] = []
                self.strings: List[StringLiteral] = []

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                decorators = [self._get_name(d) for d in node.decorator_list]
                self.functions.append(
                    FunctionDefinition(
                        line=node.lineno,
                        name=node.name,
                        full_definition="",
                        args=[arg.arg for arg in node.args.args],
                        decorators=[d for d in decorators if d is not None] or []
                    )
                )
                self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                bases = [self._get_name(base) for base in node.bases]
                self.classes.append(
                    ClassDefinition(
                        line=node.lineno,
                        name=node.name,
                        full_definition="",
                        bases=[b for b in bases if b is not None] or []
                    )
                )
                self.generic_visit(node)

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    self.imports.append(
                        ImportInfo(
                            name=alias.name,
                            asname=alias.asname,
                            line=node.lineno
                        )
                    )
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                module = node.module or ""
                for alias in node.names:
                    self.imports.append(
                        ImportInfo(
                            module=module,
                            name=alias.name,
                            asname=alias.asname,
                            line=node.lineno
                        )
                    )
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                func_name = self._get_name(node.func)
                if func_name:
                    self.calls.append(
                        CallExpression(
                            line=node.lineno,
                            function=func_name,
                            args_count=len(node.args)
                        )
                    )
                self.generic_visit(node)

            def visit_Constant(self, node: ast.Constant) -> None:
                if isinstance(node.value, str) and len(node.value) > 10:
                    self.strings.append(
                        StringLiteral(
                            line=node.lineno,
                            value=node.value[:100]
                        )
                    )
                self.generic_visit(node)

            def _get_name(self, node: ast.AST) -> Optional[str]:
                """获取节点名称"""
                if isinstance(node, ast.Name):
                    return node.id
                elif isinstance(node, ast.Attribute):
                    return f"{self._get_name(node.value)}.{node.attr}"
                return None

        visitor = ASTVisitor()
        visitor.visit(tree)

        complexity_score = self._calculate_ast_complexity(tree)

        return ASTInfo(
            functions=visitor.functions,
            classes=visitor.classes,
            imports=visitor.imports,
            calls=visitor.calls,
            strings=visitor.strings,
            complexity_score=complexity_score
        )

    def _calculate_complexity_metrics(self, content: str, lines: List[str]) -> ComplexityMetrics:
        """计算代码复杂度指标"""
        lines_of_code = 0
        comment_lines = 0
        blank_lines = 0
        cyclomatic_complexity = 0

        # 基础统计
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                blank_lines += 1
            elif line_stripped.startswith("#"):
                comment_lines += 1
            else:
                lines_of_code += 1

        # Cyclomatic complexity (simplified version)
        complexity_keywords = ["if", "elif", "for", "while", "except", "and", "or"]
        for line in lines:
            line_lower = line.lower()
            for keyword in complexity_keywords:
                cyclomatic_complexity += line_lower.count(keyword)

        return ComplexityMetrics(
            cyclomatic_complexity=cyclomatic_complexity,
            cognitive_complexity=0,  # TODO: Implement cognitive complexity
            lines_of_code=lines_of_code,
            comment_lines=comment_lines,
            blank_lines=blank_lines,
            halstead_metrics=None  # TODO: Implement Halstead metrics
        )

    def _calculate_ast_complexity(self, tree: ast.AST) -> int:
        """计算AST复杂度"""
        complexity = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.AsyncFunctionDef)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1

        return complexity

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
        )

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "基础代码分析器",
            "features": ["安全文件读取", "语法验证", "预分析处理", "AST分析支持", "复杂度计算"],
        }
