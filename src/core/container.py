#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
依赖注入容器模块
实现轻量级的依赖注入,管理所有核心组件的生命周期
"""

import asyncio
from typing import Dict, Any, Type, Optional, List
from pathlib import Path

from .interfaces import (
    ICodeAnalyzer, IReportGenerator, IConfigManager,
    ICacheManager, IProgressReporter, IPluginManager,
    IErrorHandler, ICodePrivacyManager, IAuthenticationManager,
    AppConfig, AnalyzerConfig, ReportConfig, SecurityConfig
)


class DependencyContainer:
    """依赖注入容器 - 管理所有组件的依赖关系"""

    def __init__(self):
        self._components: Dict[str, Any] = {}
        self._config: Optional[AppConfig] = None
        self._initialized = False

    def register(self, interface: Type, implementation: Any, name: str = None) -> None:
        """注册组件到容器"""
        key = name or interface.__name__
        self._components[key] = implementation

    def register_instance(self, name: str, instance: Any) -> None:
        """注册组件实例"""
        self._components[name] = instance

    def resolve(self, interface: Type, name: str = None) -> Any:
        """从容器中解析组件"""
        key = name or interface.__name__
        if key not in self._components:
            available_components = list(self._components.keys())
            available_interfaces = [comp.__class__.__name__ for comp in self._components.values()]
            raise KeyError(
                f"组件 '{key}' 未在容器中注册.\n"
                f"请求的接口: {interface.__name__}\n"
                f"可用的组件: {available_components}\n"
                f"已注册的接口类型: {available_interfaces}\n"
                f"请确保在解析前已正确注册所需组件."
            )
        return self._components[key]

    def is_registered(self, interface: Type, name: str = None) -> bool:
        """检查组件是否已注册"""
        key = name or interface.__name__
        return key in self._components

    async def initialize(self, config: Optional[AppConfig] = None) -> None:
        """初始化容器和所有组件"""
        if self._initialized:
            return

        # 加载配置
        if config is None:
            config_manager = self.resolve(IConfigManager)
            config_dict = await config_manager.load_config()
            config = self._dict_to_config(config_dict)

        self._config = config

        # 初始化各组件
        await self._initialize_components()
        self._initialized = True

    def _dict_to_config(self, config_dict: Dict[str, Any]) -> AppConfig:
        """将字典转换为配置对象"""
        return AppConfig(
            analyzer=AnalyzerConfig(**config_dict.get('analyzer', {})),
            report=ReportConfig(**config_dict.get('report', {})),
            security=SecurityConfig(**config_dict.get('security', {}))
        )

    async def _initialize_components(self) -> None:
        """初始化各组件"""
        # 配置管理器
        if not self.is_registered(IConfigManager):
            from ..infrastructure.config_manager import JsonConfigManager
            self.register(IConfigManager, JsonConfigManager())

        # 缓存管理器
        if not self.is_registered(ICacheManager) and self._config.analyzer.cache_enabled:
            from ..infrastructure.cache_manager import FileCacheManager
            cache_manager = FileCacheManager(ttl=self._config.analyzer.cache_ttl)
            self.register(ICacheManager, cache_manager)

        # 进度报告器
        if not self.is_registered(IProgressReporter):
            from ..infrastructure.progress_reporter import TqdmProgressReporter
            self.register(IProgressReporter, TqdmProgressReporter())

        # 错误处理器
        if not self.is_registered(IErrorHandler):
            from ..infrastructure.error_handler import FriendlyErrorHandler
            self.register(IErrorHandler, FriendlyErrorHandler())

        # 代码隐私管理器
        if not self.is_registered(ICodePrivacyManager) and self._config.security.enable_privacy_check:
            from ..infrastructure.privacy_manager import RegexPrivacyManager
            self.register(ICodePrivacyManager, RegexPrivacyManager())

        # 认证管理器（可选）
        if not self.is_registered(IAuthenticationManager):
            from ..infrastructure.auth_manager import SimpleAuthManager
            self.register(IAuthenticationManager, SimpleAuthManager())

        # 插件管理器
        if not self.is_registered(IPluginManager):
            from ..infrastructure.plugin_manager import DynamicPluginManager
            plugin_manager = DynamicPluginManager()
            plugin_dir = Path("plugins")
            if plugin_dir.exists():
                plugin_manager.load_plugins(str(plugin_dir))
            self.register(IPluginManager, plugin_manager)

        # 分析器
        await self._initialize_analyzers()

        # 报告生成器
        await self._initialize_reporters()

    async def _initialize_analyzers(self) -> None:
        """初始化分析器"""
        # 获取AI分析器配置
        ai_enabled = self._can_use_ai_analyzer()

        # 总是注册本地分析器
        from ..application.local_analyzer import LocalCodeAnalyzer
        local_analyzer = LocalCodeAnalyzer(
            concurrent_limit=self._config.analyzer.concurrent_limit
        )
        self.register(ICodeAnalyzer, local_analyzer, "local")

        if ai_enabled:
            # 注册AI分析器
            from ..application.ai_analyzer import AICodeAnalyzer
            ai_analyzer = AICodeAnalyzer(
                model=self._config.analyzer.ai_model,
                timeout=self._config.analyzer.api_timeout,
                max_retries=self._config.analyzer.max_retries,
                base_url=self._config.analyzer.base_url
            )
            self.register(ICodeAnalyzer, ai_analyzer, "ai")

            # 注册混合分析器（AI+本地规则）
            from ..application.hybrid_analyzer import HybridCodeAnalyzer
            hybrid_analyzer = HybridCodeAnalyzer(
                ai_analyzer=self.resolve(ICodeAnalyzer, "ai"),
                local_analyzer=self.resolve(ICodeAnalyzer, "local")
            )
            self.register(ICodeAnalyzer, hybrid_analyzer, "hybrid")
        else:
            # 没有AI时，将混合分析器重定向到本地分析器
            self.register(ICodeAnalyzer, local_analyzer, "hybrid")

        # 注册多语言分析器（基于混合分析器或本地分析器）
        from ..application.multi_language_analyzer import MultiLanguageAnalyzer
        base_analyzer = self.resolve(ICodeAnalyzer, "hybrid")
        multi_language_analyzer = MultiLanguageAnalyzer(base_analyzer)
        self.register(ICodeAnalyzer, multi_language_analyzer, "multi_language")

    def _can_use_ai_analyzer(self) -> bool:
        """检查是否可以使用AI分析器"""
        import os
        return bool(os.getenv('OPENAI_API_KEY'))

    async def _initialize_reporters(self) -> None:
        """初始化报告生成器"""
        from ..application.report_generators import (
            ConsoleReportGenerator, MarkdownReportGenerator,
            JsonReportGenerator, HtmlReportGenerator
        )

        # 控制台报告生成器
        console_reporter = ConsoleReportGenerator()
        self.register(IReportGenerator, console_reporter, "console")

        # Markdown报告生成器
        markdown_reporter = MarkdownReportGenerator()
        self.register(IReportGenerator, markdown_reporter, "markdown")

        # JSON报告生成器
        json_reporter = JsonReportGenerator()
        self.register(IReportGenerator, json_reporter, "json")

        # HTML报告生成器
        html_reporter = HtmlReportGenerator()
        self.register(IReportGenerator, html_reporter, "html")

    def get_config(self) -> AppConfig:
        """获取应用配置"""
        if not self._config:
            raise RuntimeError("Container not initialized")
        return self._config

    def cleanup(self) -> None:
        """清理资源"""
        for component in self._components.values():
            if hasattr(component, 'cleanup'):
                component.cleanup()
        self._components.clear()
        self._initialized = False


# 全局容器实例
container = DependencyContainer()


def get_container() -> DependencyContainer:
    """获取全局容器实例"""
    return container


def register_component(interface: Type, implementation: Any, name: str = None) -> None:
    """注册组件到全局容器"""
    container.register(interface, implementation, name)


def resolve_component(interface: Type, name: str = None) -> Any:
    """从全局容器解析组件"""
    return container.resolve(interface, name)


async def initialize_container(config: Optional[AppConfig] = None) -> None:
    """初始化全局容器"""
    await container.initialize(config)


def cleanup_container() -> None:
    """清理全局容器"""
    container.cleanup()