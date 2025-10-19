#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输入验证模块
提供文件验证、路径安全检查、内容过滤等功能
"""

import re
import os
import mimetypes
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """验证结果"""

    is_valid: bool
    message: str
    risk_level: str = "low"  # low, medium, high, critical
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class FileValidator:
    """文件验证器"""

    def __init__(self):
        # 定义允许的文件扩展名
        self.allowed_extensions = {
            ".py",
            ".pyw",
            ".pyx",
            ".pxd",  # Python文件
            ".js",
            ".ts",
            ".jsx",
            ".tsx",  # JavaScript/TypeScript
            ".java",
            ".kt",
            ".scala",  # JVM语言
            ".go",
            ".rs",
            ".c",
            ".cpp",
            ".h",
            ".hpp",  # 系统编程语言
            ".rb",
            ".php",
            ".swift",
            ".m",
            ".mm",  # 其他语言
            ".html",
            ".css",
            ".scss",
            ".sass",
            ".less",  # Web前端
            ".sql",
            ".xml",
            ".json",
            ".yaml",
            ".yml",
            ".toml",  # 数据文件
            ".md",
            ".txt",
            ".rst",  # 文档文件
        }

        # 定义禁止的文件模式（安全风险文件）
        self.blocked_patterns = {
            r".*\.exe$",  # 可执行文件
            r".*\.dll$",  # 动态链接库
            r".*\.so$",  # 共享库
            r".*\.dylib$",  # macOS动态库
            r".*\.bat$",  # 批处理文件
            r".*\.sh$",  # Shell脚本
            r".*\.ps1$",  # PowerShell脚本
            r".*\.vbs$",  # VBScript
            r".*\.jar$",  # Java归档
            r".*\.zip$",  # 压缩文件
            r".*\.rar$",
            r".*\.7z$",
            r".*\.tar$",
            r".*\.gz$",
            r".*\.bz2$",
            r".*\.__pycache__.*",  # Python缓存
            r".*\.git.*",  # Git相关
            r".*\.svn.*",  # SVN相关
            r".*\.DS_Store$",  # macOS系统文件
            r".*Thumbs\.db$",  # Windows缩略图缓存
        }

        # 编译正则表达式
        self.blocked_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.blocked_patterns]

        # 文件大小限制 (MB)
        self.max_file_size_mb = 50
        self.min_file_size_bytes = 10  # 最小文件大小

        # 文件内容模式检查
        self.suspicious_patterns = {
            "potential_binary": re.compile(rb"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]"),
            "control_characters": re.compile(rb"[\x00-\x08\x0B-\x0C\x0E-\x1F]"),
            "high_ascii": re.compile(rb"[\x80-\xFF]"),
        }

    def validate_file_path(self, file_path: Path) -> ValidationResult:
        """验证文件路径"""
        try:
            # 基本路径验证
            if not file_path.exists():
                return ValidationResult(is_valid=False, message=f"文件不存在: {file_path}", risk_level="high")

            if not file_path.is_file():
                return ValidationResult(is_valid=False, message=f"路径不是文件: {file_path}", risk_level="medium")

            # 路径遍历检查
            resolved_path = file_path.resolve()
            if ".." in str(file_path) or not str(resolved_path).startswith(str(Path.cwd().resolve())):
                return ValidationResult(
                    is_valid=False, message=f"检测到潜在的路径遍历攻击: {file_path}", risk_level="critical"
                )

            # 文件扩展名检查
            extension = file_path.suffix.lower()
            if extension not in self.allowed_extensions:
                return ValidationResult(
                    is_valid=False,
                    message=f"不支持的文件类型: {extension}",
                    risk_level="high",
                    details={"extension": extension, "allowed_extensions": list(self.allowed_extensions)},
                )

            # 阻止模式检查
            file_name = file_path.name
            for pattern_regex in self.blocked_regexes:
                if pattern_regex.match(file_name):
                    return ValidationResult(
                        is_valid=False,
                        message=f"文件类型被阻止: {file_name}",
                        risk_level="critical",
                        details={"matched_pattern": pattern_regex.pattern},
                    )

            # 符号链接检查
            if file_path.is_symlink():
                return ValidationResult(is_valid=False, message="不允许分析符号链接文件", risk_level="high")

            return ValidationResult(is_valid=True, message=f"文件路径验证通过: {file_path}", risk_level="low")

        except Exception as e:
            logger.error(f"文件路径验证出错: {e}")
            return ValidationResult(is_valid=False, message=f"文件路径验证失败: {str(e)}", risk_level="high")

    def validate_file_size(self, file_path: Path) -> ValidationResult:
        """验证文件大小"""
        try:
            file_size = file_path.stat().st_size

            # 检查最小文件大小
            if file_size < self.min_file_size_bytes:
                return ValidationResult(
                    is_valid=False, message=f"文件太小({file_size}字节),可能不是有效的代码文件", risk_level="medium"
                )

            # 检查最大文件大小
            file_size_mb = file_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                return ValidationResult(
                    is_valid=False,
                    message=f"文件过大({file_size_mb:.1f} MB),超过最大限制{self.max_file_size_mb} MB",
                    risk_level="high",
                    details={"file_size_mb": file_size_mb, "max_size_mb": self.max_file_size_mb},
                )

            # 警告大文件
            if file_size_mb > 10:
                return ValidationResult(
                    is_valid=True,
                    message=f"文件较大({file_size_mb:.1f} MB),分析可能需要较长时间",
                    risk_level="medium",
                    details={"file_size_mb": file_size_mb},
                )

            return ValidationResult(
                is_valid=True, message=f"文件大小验证通过（{file_size_mb:.1f} MB）", risk_level="low"
            )

        except Exception as e:
            logger.error(f"文件大小验证出错: {e}")
            return ValidationResult(is_valid=False, message=f"文件大小验证失败: {str(e)}", risk_level="high")

    def validate_file_content(self, file_path: Path) -> ValidationResult:
        """验证文件内容"""
        try:
            # 读取文件头进行内容检查
            with open(file_path, "rb") as f:
                header = f.read(8192)  # 读取前8KB

            if not header:
                return ValidationResult(is_valid=False, message="文件内容为空", risk_level="medium")

            # 检查二进制内容
            if self.suspicious_patterns["potential_binary"].search(header):
                binary_ratio = self._calculate_binary_ratio(header)
                if binary_ratio > 0.1:  # 超过10%的二进制字符
                    return ValidationResult(
                        is_valid=False,
                        message=f"文件包含大量二进制内容({binary_ratio*100:.1f}%),可能不是文本文件",
                        risk_level="high",
                        details={"binary_ratio": binary_ratio},
                    )

            # 检查控制字符
            if self.suspicious_patterns["control_characters"].search(header):
                return ValidationResult(
                    is_valid=False, message="文件包含控制字符,可能不是有效的代码文件", risk_level="high"
                )

            # 尝试检测文件编码
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    f.read(1024)  # 尝试读取一部分
            except UnicodeDecodeError:
                # 尝试其他编码
                detected_encoding = self._detect_encoding(header)
                if detected_encoding:
                    return ValidationResult(
                        is_valid=True,
                        message=f"文件使用{detected_encoding}编码,将尝试转换",
                        risk_level="low",
                        details={"encoding": detected_encoding},
                    )
                else:
                    return ValidationResult(is_valid=False, message="无法识别的文件编码", risk_level="high")

            # 检查文件类型（使用python-magic）
            mime_type = self._get_mime_type(file_path)
            if mime_type and not mime_type.startswith("text/"):
                return ValidationResult(
                    is_valid=False,
                    message=f"文件类型不是文本文件（{mime_type}）",
                    risk_level="high",
                    details={"mime_type": mime_type},
                )

            return ValidationResult(
                is_valid=True,
                message="文件内容验证通过",
                risk_level="low",
                details={"mime_type": mime_type or "text/plain"},
            )

        except Exception as e:
            logger.error(f"文件内容验证出错: {e}")
            return ValidationResult(is_valid=False, message=f"文件内容验证失败: {str(e)}", risk_level="high")

    def validate_file_permissions(self, file_path: Path) -> ValidationResult:
        """验证文件权限"""
        try:
            # 检查文件是否可读
            if not os.access(file_path, os.R_OK):
                return ValidationResult(is_valid=False, message="文件不可读（权限不足）", risk_level="high")

            # 检查文件是否可写(可选,主要用于缓存目录)
            parent_dir = file_path.parent
            if not os.access(parent_dir, os.W_OK):
                return ValidationResult(
                    is_valid=True, message="文件所在目录不可写,缓存功能可能受影响", risk_level="medium"
                )

            # 检查文件所有者
            try:
                file_stat = file_path.stat()
                current_uid = os.getuid() if hasattr(os, "getuid") else None

                if current_uid and file_stat.st_uid != current_uid:
                    return ValidationResult(
                        is_valid=True, message=f"文件所有者与当前用户不同（UID: {file_stat.st_uid}）", risk_level="low"
                    )

            except (AttributeError, OSError):
                # Windows系统或不支持UID的系统
                pass

            return ValidationResult(is_valid=True, message="文件权限验证通过", risk_level="low")

        except Exception as e:
            logger.error(f"文件权限验证出错: {e}")
            return ValidationResult(is_valid=False, message=f"文件权限验证失败: {str(e)}", risk_level="high")

    def comprehensive_validate(self, file_path: Path) -> Tuple[bool, List[ValidationResult]]:
        """综合验证文件"""
        results = []

        # 1. 路径验证
        path_result = self.validate_file_path(file_path)
        results.append(path_result)
        if not path_result.is_valid:
            return False, results

        # 2. 大小验证
        size_result = self.validate_file_size(file_path)
        results.append(size_result)

        # 3. 内容验证
        content_result = self.validate_file_content(file_path)
        results.append(content_result)

        # 4. 权限验证
        permission_result = self.validate_file_permissions(file_path)
        results.append(permission_result)

        # 综合判断
        overall_valid = all(result.is_valid for result in results)

        return overall_valid, results

    def _calculate_binary_ratio(self, data: bytes) -> float:
        """计算二进制字符比例"""
        if not data:
            return 0.0

        binary_chars = sum(1 for byte in data if byte < 32 and byte not in (9, 10, 13))
        return binary_chars / len(data)

    def _detect_encoding(self, data: bytes) -> Optional[str]:
        """检测文件编码"""
        try:
            import chardet

            result = chardet.detect(data)
            return result.get("encoding") if result and result.get("confidence", 0) > 0.7 else None
        except ImportError:
            # 如果没有安装chardet,使用简单的启发式方法
            encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]
            for encoding in encodings:
                try:
                    data.decode(encoding)
                    return encoding
                except UnicodeDecodeError:
                    continue
            return None

    def _get_mime_type(self, file_path: Path) -> Optional[str]:
        """获取文件的MIME类型"""
        try:
            # 尝试使用python-magic
            import magic

            mime = magic.Magic(mime=True)
            return mime.from_file(str(file_path))
        except ImportError:
            # 回退到mimetypes
            mime_type, _ = mimetypes.guess_type(str(file_path))
            return mime_type


class ContentSanitizer:
    """内容清理器"""

    def __init__(self):
        # 危险代码模式
        self.dangerous_patterns = [
            re.compile(r"__import__\s*\("),
            re.compile(r"eval\s*\("),
            re.compile(r"exec\s*\("),
            re.compile(r"compile\s*\("),
            re.compile(r"open\s*\(.*[\"\'].*[\"\'].*[,\)]"),
            re.compile(r"os\.system\s*\("),
            re.compile(r"subprocess\."),
            re.compile(r"input\s*\("),
            re.compile(r"raw_input\s*\("),
        ]

    def sanitize_content(self, content: str) -> str:
        """清理内容中的危险代码"""
        sanitized = content

        for pattern in self.dangerous_patterns:
            sanitized = pattern.sub("# 潜在危险代码已移除", sanitized)

        return sanitized

    def validate_content_safety(self, content: str) -> ValidationResult:
        """验证内容安全性"""
        dangerous_matches = []

        for pattern in self.dangerous_patterns:
            matches = pattern.findall(content)
            if matches:
                dangerous_matches.extend(matches)

        if dangerous_matches:
            return ValidationResult(
                is_valid=False,
                message=f"检测到潜在危险代码: {dangerous_matches[:3]}",
                risk_level="high",
                details={"dangerous_patterns": dangerous_matches[:5]},
            )

        return ValidationResult(is_valid=True, message="内容安全检查通过", risk_level="low")


# 全局验证器实例
_file_validator = FileValidator()
_content_sanitizer = ContentSanitizer()


def validate_file_safety(file_path: Path) -> Tuple[bool, List[ValidationResult]]:
    """验证文件安全性（便捷函数）"""
    return _file_validator.comprehensive_validate(file_path)


def sanitize_code_content(content: str) -> str:
    """清理代码内容（便捷函数）"""
    return _content_sanitizer.sanitize_content(content)


def validate_content_safety(content: str) -> ValidationResult:
    """验证内容安全性（便捷函数）"""
    return _content_sanitizer.validate_content_safety(content)
