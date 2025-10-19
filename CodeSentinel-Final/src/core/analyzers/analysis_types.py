#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analysis data types module
Defines structured data types for analysis results
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class ImportStatement:
    """Represents an import statement"""
    line: int
    module: str
    full_statement: str


@dataclass
class FunctionDefinition:
    """Represents a function definition"""
    line: int
    name: str
    full_definition: str
    args: Optional[List[str]] = None
    decorators: Optional[List[str]] = None


@dataclass
class ClassDefinition:
    """Represents a class definition"""
    line: int
    name: str
    full_definition: str
    bases: Optional[List[str]] = None


@dataclass
class CallExpression:
    """Represents a function call"""
    line: int
    function: str
    args_count: int


@dataclass
class StringLiteral:
    """Represents a string literal in code"""
    line: int
    value: str


@dataclass
class ImportInfo:
    """Import information from AST"""
    name: Optional[str] = None
    module: Optional[str] = None
    asname: Optional[str] = None
    line: Optional[int] = None


@dataclass
class HalsteadMetrics:
    """Halstead complexity metrics"""
    operators: int = 0
    operands: int = 0
    distinct_operators: int = 0
    distinct_operands: int = 0
    vocabulary: int = 0
    length: int = 0
    calculated_length: float = 0.0
    volume: float = 0.0
    difficulty: float = 0.0
    effort: float = 0.0


@dataclass
class ComplexityMetrics:
    """Code complexity metrics"""
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    lines_of_code: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    halstead_metrics: Optional[HalsteadMetrics] = None


@dataclass
class ASTInfo:
    """AST analysis information"""
    functions: List[FunctionDefinition]
    classes: List[ClassDefinition]
    imports: List[ImportInfo]
    calls: List[CallExpression]
    strings: List[StringLiteral]
    complexity_score: int


@dataclass
class RiskPattern:
    """Represents a potential risk pattern"""
    pattern: str
    line: int
    severity: str
    description: str


@dataclass
class PreAnalysisInfo:
    """Pre-analysis information"""
    total_lines: int
    code_lines: int
    import_statements: List[ImportStatement]
    function_definitions: List[FunctionDefinition]
    class_definitions: List[ClassDefinition]
    potential_risk_patterns: List[RiskPattern]
    complexity_metrics: ComplexityMetrics
    ast_info: ASTInfo


# Helper functions to convert between Dict and dataclass
def dict_to_pre_analysis_info(data: Dict[str, Any]) -> PreAnalysisInfo:
    """Convert dictionary to PreAnalysisInfo"""
    import_statements = [
        ImportStatement(**stmt) for stmt in data.get("import_statements", [])
    ]

    function_definitions = [
        FunctionDefinition(**func) for func in data.get("function_definitions", [])
    ]

    class_definitions = [
        ClassDefinition(**cls) for cls in data.get("class_definitions", [])
    ]

    risk_patterns = [
        RiskPattern(**pattern) for pattern in data.get("potential_risk_patterns", [])
    ]

    complexity_data = data.get("complexity_metrics", {})
    halstead_data = complexity_data.get("halstead_metrics", {})

    complexity_metrics = ComplexityMetrics(
        cyclomatic_complexity=complexity_data.get("cyclomatic_complexity", 0),
        cognitive_complexity=complexity_data.get("cognitive_complexity", 0),
        lines_of_code=complexity_data.get("lines_of_code", 0),
        comment_lines=complexity_data.get("comment_lines", 0),
        blank_lines=complexity_data.get("blank_lines", 0),
        halstead_metrics=HalsteadMetrics(**halstead_data) if halstead_data else None
    )

    ast_data = data.get("ast_info", {})
    ast_functions = [
        FunctionDefinition(
            line=func.get("line", 0),
            name=func.get("name", ""),
            full_definition="",
            args=func.get("args", []),
            decorators=func.get("decorators", [])
        )
        for func in ast_data.get("functions", [])
    ]

    ast_classes = [
        ClassDefinition(
            line=cls.get("line", 0),
            name=cls.get("name", ""),
            full_definition="",
            bases=cls.get("bases", [])
        )
        for cls in ast_data.get("classes", [])
    ]

    ast_imports = [
        ImportInfo(**imp) for imp in ast_data.get("imports", [])
    ]

    ast_calls = [
        CallExpression(**call) for call in ast_data.get("calls", [])
    ]

    ast_strings = [
        StringLiteral(**s) for s in ast_data.get("strings", [])
    ]

    ast_info = ASTInfo(
        functions=ast_functions,
        classes=ast_classes,
        imports=ast_imports,
        calls=ast_calls,
        strings=ast_strings,
        complexity_score=ast_data.get("complexity_score", 0)
    )

    return PreAnalysisInfo(
        total_lines=data.get("total_lines", 0),
        code_lines=data.get("code_lines", 0),
        import_statements=import_statements,
        function_definitions=function_definitions,
        class_definitions=class_definitions,
        potential_risk_patterns=risk_patterns,
        complexity_metrics=complexity_metrics,
        ast_info=ast_info
    )


def pre_analysis_info_to_dict(info: PreAnalysisInfo) -> Dict[str, Any]:
    """Convert PreAnalysisInfo to dictionary"""
    return {
        "total_lines": info.total_lines,
        "code_lines": info.code_lines,
        "import_statements": [
            {
                "line": stmt.line,
                "module": stmt.module,
                "full_statement": stmt.full_statement
            }
            for stmt in info.import_statements
        ],
        "function_definitions": [
            {
                "line": func.line,
                "name": func.name,
                "full_definition": func.full_definition,
                "args": func.args or [],
                "decorators": func.decorators or []
            }
            for func in info.function_definitions
        ],
        "class_definitions": [
            {
                "line": cls.line,
                "name": cls.name,
                "full_definition": cls.full_definition,
                "bases": cls.bases or []
            }
            for cls in info.class_definitions
        ],
        "potential_risk_patterns": [
            {
                "pattern": pattern.pattern,
                "line": pattern.line,
                "severity": pattern.severity,
                "description": pattern.description
            }
            for pattern in info.potential_risk_patterns
        ],
        "complexity_metrics": {
            "cyclomatic_complexity": info.complexity_metrics.cyclomatic_complexity,
            "cognitive_complexity": info.complexity_metrics.cognitive_complexity,
            "lines_of_code": info.complexity_metrics.lines_of_code,
            "comment_lines": info.complexity_metrics.comment_lines,
            "blank_lines": info.complexity_metrics.blank_lines,
            "halstead_metrics": {
                "operators": info.complexity_metrics.halstead_metrics.operators,
                "operands": info.complexity_metrics.halstead_metrics.operands,
                "distinct_operators": info.complexity_metrics.halstead_metrics.distinct_operators,
                "distinct_operands": info.complexity_metrics.halstead_metrics.distinct_operands,
                "vocabulary": info.complexity_metrics.halstead_metrics.vocabulary,
                "length": info.complexity_metrics.halstead_metrics.length,
                "calculated_length": info.complexity_metrics.halstead_metrics.calculated_length,
                "volume": info.complexity_metrics.halstead_metrics.volume,
                "difficulty": info.complexity_metrics.halstead_metrics.difficulty,
                "effort": info.complexity_metrics.halstead_metrics.effort,
            } if info.complexity_metrics.halstead_metrics else {}
        },
        "ast_info": {
            "functions": [
                {
                    "name": func.name,
                    "line": func.line,
                    "args": func.args or [],
                    "decorators": func.decorators or []
                }
                for func in info.ast_info.functions
            ],
            "classes": [
                {
                    "name": cls.name,
                    "line": cls.line,
                    "bases": cls.bases or []
                }
                for cls in info.ast_info.classes
            ],
            "imports": [
                {
                    "name": imp.name,
                    "module": imp.module,
                    "asname": imp.asname,
                    "line": imp.line
                }
                for imp in info.ast_info.imports
            ],
            "calls": [
                {
                    "function": call.function,
                    "line": call.line,
                    "args_count": call.args_count
                }
                for call in info.ast_info.calls
            ],
            "strings": [
                {
                    "value": string.value,
                    "line": string.line
                }
                for string in info.ast_info.strings
            ],
            "complexity_score": info.ast_info.complexity_score
        }
    }