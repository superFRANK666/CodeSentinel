#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理器实现模块
支持多种配置格式(JSON、YAML、TOML)和环境变量
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from ..core.interfaces import IConfigManager, AppConfig, AnalyzerConfig, ReportConfig, SecurityConfig


class JsonConfigManager(IConfigManager):
    """JSON配置文件管理器"""

    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.default_config_file = self.config_dir / "default.json"
        self.user_config_file = self.config_dir / "config.json"
        self._config_cache: Optional[Dict[str, Any]] = None

    async def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """加载配置"""
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = self.user_config_file if self.user_config_file.exists() else self.default_config_file

        try:
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
            else:
                file_config = self._get_default_config()
                # 创建默认配置文件
                await self.save_config(file_config, str(self.default_config_file))

            # 合并环境变量配置
            env_config = self._load_env_config()
            merged_config = self._merge_configs(file_config, env_config)

            self._config_cache = merged_config
            return merged_config

        except Exception as e:
            # 如果配置文件加载失败,返回默认配置
            return self._get_default_config()

    async def save_config(self, config: Dict[str, Any], config_path: str) -> None:
        """保存配置"""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        if self._config_cache is None:
            return default
        return self._get_nested_value(self._config_cache, key, default)

    def set(self, key: str, value: Any) -> None:
        """设置配置项"""
        if self._config_cache is None:
            self._config_cache = self._get_default_config()
        self._set_nested_value(self._config_cache, key, value)

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "analyzer": {
                "severity_threshold": "low",
                "max_file_size": 1024,
                "concurrent_limit": 5,
                "cache_enabled": True,
                "cache_ttl": 3600,
                "ai_model": "gpt-4o-mini",
                "api_timeout": 60,
                "max_retries": 3
            },
            "report": {
                "formats": ["console", "markdown"],
                "output_dir": "./reports",
                "include_code_snippets": True,
                "include_remediation": True,
                "max_vulnerabilities": 1000
            },
            "security": {
                "enable_privacy_check": True,
                "enable_code_sanitization": False,
                "allowed_file_extensions": [".py"],
                "blocked_patterns": ["*.pyc", "__pycache__", "*.so", "*.dll"]
            }
        }

    def _load_env_config(self) -> Dict[str, Any]:
        """从环境变量加载配置-修复版本"""
        env_config = {}

        # OpenAI配置-只包含配置文件中存在的字段
        if os.getenv('OPENAI_MODEL'):
            env_config.setdefault('analyzer', {})['ai_model'] = os.getenv('OPENAI_MODEL')
        if os.getenv('OPENAI_API_BASE'):
            env_config.setdefault('analyzer', {})['base_url'] = os.getenv('OPENAI_API_BASE')

        # 超时配置
        if os.getenv('REQUEST_TIMEOUT'):
            env_config.setdefault('analyzer', {})['api_timeout'] = int(os.getenv('REQUEST_TIMEOUT'))
        if os.getenv('MAX_RETRIES'):
            env_config.setdefault('analyzer', {})['max_retries'] = int(os.getenv('MAX_RETRIES'))

        # 日志配置
        if os.getenv('LOG_LEVEL'):
            env_config.setdefault('logging', {})['level'] = os.getenv('LOG_LEVEL')
        if os.getenv('VERBOSE_LOGGING'):
            env_config.setdefault('logging', {})['verbose'] = os.getenv('VERBOSE_LOGGING').lower() == 'true'

        return env_config

    def _merge_configs(self, base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
        """合并配置"""
        result = base_config.copy()

        for key, value in override_config.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    def _get_nested_value(self, config: Dict[str, Any], key: str, default: Any = None) -> Any:
        """获取嵌套配置值"""
        keys = key.split('.')
        current = config

        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default

        return current

    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any) -> None:
        """设置嵌套配置值"""
        keys = key.split('.')
        current = config

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

    def create_default_config_file(self) -> None:
        """创建默认配置文件"""
        default_config = self._get_default_config()
        self.user_config_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.user_config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """验证配置有效性"""
        try:
            # 基本结构验证
            required_sections = ['analyzer', 'report', 'security']
            for section in required_sections:
                if section not in config:
                    return False

            # 数值范围验证
            analyzer_config = config.get('analyzer', {})
            if not 1 <= analyzer_config.get('concurrent_limit', 1) <= 20:
                return False
            if not 64 <= analyzer_config.get('max_file_size', 1024) <= 100 * 1024:
                return False

            return True
        except Exception:
            return False


class YamlConfigManager(IConfigManager):
    """YAML配置文件管理器"""

    def __init__(self, config_dir: str = "./config"):
        try:
            import yaml
            self.yaml = yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML config support. Install with: pip install PyYAML")

        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.default_config_file = self.config_dir / "default.yaml"
        self.user_config_file = self.config_dir / "config.yaml"
        self._config_cache: Optional[Dict[str, Any]] = None

    async def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """加载配置"""
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = self.user_config_file if self.user_config_file.exists() else self.default_config_file

        try:
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_config = self.yaml.safe_load(f) or {}
            else:
                file_config = self._get_default_config()
                await self.save_config(file_config, str(self.default_config_file))

            env_config = self._load_env_config()
            merged_config = self._merge_configs(file_config, env_config)

            self._config_cache = merged_config
            return merged_config

        except Exception:
            return self._get_default_config()

    async def save_config(self, config: Dict[str, Any], config_path: str) -> None:
        """保存配置"""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)

        with open(config_file, 'w', encoding='utf-8') as f:
            self.yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        if self._config_cache is None:
            return default
        return JsonConfigManager._get_nested_value(self._config_cache, key, default)

    def set(self, key: str, value: Any) -> None:
        """设置配置项"""
        if self._config_cache is None:
            self._config_cache = self._get_default_config()
        JsonConfigManager._set_nested_value(self._config_cache, key, value)

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return JsonConfigManager()._get_default_config()

    def _load_env_config(self) -> Dict[str, Any]:
        """从环境变量加载配置"""
        return JsonConfigManager()._load_env_config()

    def _merge_configs(self, base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
        """合并配置"""
        return JsonConfigManager()._merge_configs(base_config, override_config)


# 配置管理器工厂
class ConfigManagerFactory:
    """配置管理器工厂"""

    @staticmethod
    def create_config_manager(config_type: str = "json", config_dir: str = "./config") -> IConfigManager:
        """创建配置管理器实例"""
        if config_type.lower() == "json":
            return JsonConfigManager(config_dir)
        elif config_type.lower() == "yaml":
            return YamlConfigManager(config_dir)
        else:
            raise ValueError(f"Unsupported config type: {config_type}")