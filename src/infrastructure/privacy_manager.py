#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码隐私管理器实现模块
提供代码脱敏和隐私保护功能
"""

import re
from typing import Dict, Any, List
from ..core.interfaces import ICodePrivacyManager


class RegexPrivacyManager(ICodePrivacyManager):
    """基于正则表达式的代码隐私管理器"""

    def __init__(self):
        # 定义敏感信息模式
        self.sensitive_patterns = {
            # API密钥
            "api_key": re.compile(
                r'(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
                re.IGNORECASE,
            ),
            # 密码
            "password": re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', re.IGNORECASE),
            # 令牌
            "token": re.compile(
                r'(?i)(?:token|auth[_-]?token|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', re.IGNORECASE
            ),
            # 私钥
            "private_key": re.compile(
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----", re.MULTILINE
            ),
            # 证书
            "certificate": re.compile(
                r"-----BEGIN\s+CERTIFICATE-----[\s\S]+?-----END\s+CERTIFICATE-----", re.MULTILINE
            ),
            # 数据库连接字符串
            "database_url": re.compile(r'(?i)(?:mongodb|mysql|postgresql|postgres)://[^\s"\'\n]+', re.IGNORECASE),
            # 邮箱地址
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            # IP地址
            "ip_address": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            # 长随机字符串（可能是密钥）
            "random_string": re.compile(r'["\']?[a-zA-Z0-9_\-]{32,}["\']?'),
            # URL中的敏感参数
            "url_secret": re.compile(r"(?i)(?:api[_-]?key|token|secret|password)=[^\s\u0026]+", re.IGNORECASE),
        }

        # 替换映射
        self.replacement_map = {
            "api_key": "REDACTED_API_KEY",
            "password": "REDACTED_PASSWORD",
            "token": "REDACTED_TOKEN",
            "private_key": "REDACTED_PRIVATE_KEY",
            "certificate": "REDACTED_CERTIFICATE",
            "database_url": "REDACTED_DATABASE_URL",
            "email": "REDACTED@EMAIL.COM",
            "ip_address": "REDACTED_IP",
            "random_string": "REDACTED_STRING",
            "url_secret": "REDACTED_SECRET",
        }

        # 隐私等级配置
        self.privacy_levels = {
            "none": {"description": "不进行脱敏", "patterns": []},
            "basic": {
                "description": "基本脱敏 - 隐藏明显的敏感信息",
                "patterns": ["api_key", "password", "private_key", "certificate"],
            },
            "full": {
                "description": "完全脱敏 - 隐藏所有可能的敏感信息",
                "patterns": list(self.sensitive_patterns.keys()),
            },
        }

    def sanitize_code(self, content: str, privacy_level: str = "basic") -> str:
        """对代码进行脱敏处理"""
        if privacy_level == "none":
            return content

        if privacy_level not in self.privacy_levels:
            privacy_level = "basic"

        patterns_to_use = self.privacy_levels[privacy_level]["patterns"]
        sanitized_content = content

        for pattern_name in patterns_to_use:
            if pattern_name in self.sensitive_patterns:
                pattern = self.sensitive_patterns[pattern_name]
                replacement = self.replacement_map[pattern_name]

                # 执行替换
                sanitized_content = pattern.sub(
                    lambda m: self._create_replacement(m, pattern_name, replacement), sanitized_content
                )

        return sanitized_content

    def _create_replacement(self, match: re.Match, pattern_name: str, replacement: str) -> str:
        """创建替换文本"""
        original_text = match.group(0)

        # 保留原始格式（引号、赋值符号等）
        if "=" in original_text or ":" in original_text:
            # 处理赋值语句
            if "=" in original_text:
                parts = original_text.split("=", 1)
                return f"{parts[0]}= {replacement}"
            elif ":" in original_text:
                parts = original_text.split(":", 1)
                return f"{parts[0]}: {replacement}"

        # 处理字符串
        if original_text.startswith('"') and original_text.endswith('"'):
            return f'"{replacement}"'
        elif original_text.startswith("'") and original_text.endswith("'"):
            return f"'{replacement}'"

        return replacement

    def is_sensitive_content(self, content: str) -> bool:
        """检查是否包含敏感内容"""
        for pattern_name, pattern in self.sensitive_patterns.items():
            if pattern.search(content):
                return True
        return False

    def get_privacy_level(self, content: str) -> str:
        """获取隐私等级"""
        sensitive_count = 0
        total_patterns = len(self.sensitive_patterns)

        for pattern_name, pattern in self.sensitive_patterns.items():
            if pattern.search(content):
                sensitive_count += 1

        # 根据敏感信息密度判断隐私等级
        if sensitive_count == 0:
            return "none"
        elif sensitive_count <= total_patterns * 0.3:
            return "basic"
        else:
            return "full"

    def get_sensitive_info_summary(self, content: str) -> Dict[str, Any]:
        """获取敏感信息摘要"""
        summary = {
            "total_matches": 0,
            "pattern_matches": {},
            "privacy_level": self.get_privacy_level(content),
            "risk_assessment": "low",
        }

        total_matches = 0
        pattern_matches = {}

        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(content)
            match_count = len(matches)

            if match_count > 0:
                total_matches += match_count
                pattern_matches[pattern_name] = {
                    "count": match_count,
                    "examples": [self._mask_sensitive_info(m) for m in matches[:3]],  # 只显示前3个示例
                }

        summary["total_matches"] = total_matches
        summary["pattern_matches"] = pattern_matches

        # 风险评估
        if total_matches >= 10:
            summary["risk_assessment"] = "high"
        elif total_matches >= 3:
            summary["risk_assessment"] = "medium"
        else:
            summary["risk_assessment"] = "low"

        return summary

    def _mask_sensitive_info(self, text: str) -> str:
        """对敏感信息进行掩码处理"""
        if len(text) <= 8:
            return "*" * len(text)
        else:
            # 保留首尾字符,中间用*替换
            return text[0] + "*" * (len(text) - 2) + text[-1]

    def add_custom_pattern(self, name: str, pattern: str, replacement: str, privacy_level: str = "basic") -> None:
        """添加自定义敏感信息模式"""
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            self.sensitive_patterns[name] = compiled_pattern
            self.replacement_map[name] = replacement

            # 添加到相应的隐私等级
            if name not in self.privacy_levels[privacy_level]["patterns"]:
                self.privacy_levels[privacy_level]["patterns"].append(name)

        except re.error as e:
            raise ValueError(f"无效的正则表达式模式：{e}")

    def remove_pattern(self, name: str) -> bool:
        """移除敏感信息模式"""
        if name in self.sensitive_patterns:
            del self.sensitive_patterns[name]
            if name in self.replacement_map:
                del self.replacement_map[name]

            # 从所有隐私等级中移除
            for level_info in self.privacy_levels.values():
                if name in level_info["patterns"]:
                    level_info["patterns"].remove(name)

            return True
        return False

    def get_patterns_info(self) -> Dict[str, Any]:
        """获取所有模式的信息"""
        patterns_info = {}
        for name, pattern in self.sensitive_patterns.items():
            patterns_info[name] = {
                "pattern": pattern.pattern,
                "replacement": self.replacement_map.get(name, "REDACTED"),
                "privacy_levels": [level for level, info in self.privacy_levels.items() if name in info["patterns"]],
            }
        return patterns_info

    def create_privacy_report(self, content: str) -> Dict[str, Any]:
        """创建隐私分析报告"""
        original_summary = self.get_sensitive_info_summary(content)

        # 对不同隐私等级进行脱敏
        sanitized_results = {}
        for level in ["none", "basic", "full"]:
            sanitized_content = self.sanitize_code(content, level)
            sanitized_summary = self.get_sensitive_info_summary(sanitized_content)

            sanitized_results[level] = {
                "privacy_level": level,
                "description": self.privacy_levels[level]["description"],
                "original_length": len(content),
                "sanitized_length": len(sanitized_content),
                "reduction_ratio": (len(content) - len(sanitized_content)) / len(content) if len(content) > 0 else 0,
                "remaining_sensitive_count": sanitized_summary["total_matches"],
                "sanitized_content_preview": (
                    sanitized_content[:500] + "..." if len(sanitized_content) > 500 else sanitized_content
                ),
            }

        return {
            "original_summary": original_summary,
            "sanitized_results": sanitized_results,
            "recommendations": self._generate_privacy_recommendations(original_summary),
        }

    def _generate_privacy_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """生成隐私保护建议"""
        recommendations = []

        if summary["risk_assessment"] == "high":
            recommendations.append("代码中包含大量敏感信息,建议使用完全脱敏模式")
            recommendations.append("考虑将敏感信息移至配置文件或环境变量")
            recommendations.append("不要在代码中硬编码密钥、密码等敏感数据")

        elif summary["risk_assessment"] == "medium":
            recommendations.append("代码中包含一些敏感信息,建议使用基本脱敏")
            recommendations.append("检查是否有遗漏的敏感信息需要处理")
            recommendations.append("考虑使用更安全的敏感信息管理方式")

        else:
            recommendations.append("代码中敏感信息较少,可以选择不进行脱敏")
            recommendations.append("继续保持良好的敏感信息管理习惯")

        # 通用建议
        recommendations.extend(
            ["定期审查代码中的敏感信息", "使用密钥管理服务存储重要密钥", "实施代码审查流程,防止敏感信息泄露"]
        )

        return recommendations


class AIPrivacyManager(ICodePrivacyManager):
    """AI驱动的隐私管理器"""

    def __init__(self, ai_model=None):
        self.ai_model = ai_model
        self.regex_manager = RegexPrivacyManager()

    def sanitize_code(self, content: str, privacy_level: str = "basic") -> str:
        """使用AI和规则结合的方式进行脱敏"""
        # 首先使用规则进行基础脱敏
        sanitized_content = self.regex_manager.sanitize_code(content, privacy_level)

        # 如果有AI模型,进行智能脱敏
        if self.ai_model and privacy_level == "full":
            sanitized_content = self._ai_enhanced_sanitization(sanitized_content)

        return sanitized_content

    def _ai_enhanced_sanitization(self, content: str) -> str:
        """AI增强的脱敏处理"""
        # 这里可以集成AI模型进行更智能的敏感信息识别
        # 目前回退到规则脱敏
        return content

    def is_sensitive_content(self, content: str) -> bool:
        """检查是否包含敏感内容"""
        return self.regex_manager.is_sensitive_content(content)

    def get_privacy_level(self, content: str) -> str:
        """获取隐私等级"""
        return self.regex_manager.get_privacy_level(content)


class PrivacyManagerFactory:
    """隐私管理器工厂"""

    @staticmethod
    def create_privacy_manager(manager_type: str = "regex", **kwargs) -> ICodePrivacyManager:
        """创建隐私管理器"""
        if manager_type == "regex":
            return RegexPrivacyManager(**kwargs)
        elif manager_type == "ai":
            return AIPrivacyManager(**kwargs)
        else:
            raise ValueError(f"不支持的隐私管理器类型：{manager_type}")

    @staticmethod
    def get_privacy_levels() -> Dict[str, str]:
        """获取支持的隐私等级"""
        return {
            "none": "不进行脱敏处理",
            "basic": "基本脱敏 - 隐藏明显的敏感信息",
            "full": "完全脱敏 - 隐藏所有可能的敏感信息",
        }
