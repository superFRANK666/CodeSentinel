#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
插件管理器实现模块
支持动态加载和管理插件
"""

import os
import importlib
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import List, Dict, Any, Type, Optional, Protocol
from abc import ABC, abstractmethod

from ..core.interfaces import (
    IVulnerabilityDetector, IReportGenerator, ICodeAnalyzer,
    Vulnerability, SeverityLevel, AnalysisResult
)


logger = logging.getLogger(__name__)


class PluginMetadata:
    """插件元数据"""

    def __init__(self, name: str, version: str, description: str,
                 author: str = "", requires: List[str] = None,
                 plugin_type: str = "detector"):
        self.name = name
        self.version = version
        self.description = description
        self.author = author or "Unknown"
        self.requires = requires or []
        self.plugin_type = plugin_type
        self.enabled = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "requires": self.requires,
            "plugin_type": self.plugin_type,
            "enabled": self.enabled
        }


class BasePlugin(ABC):
    """插件基类"""

    def __init__(self):
        self.metadata = self.get_metadata()
        self.enabled = True

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """获取插件元数据"""
        pass

    def initialize(self) -> bool:
        """初始化插件"""
        return True

    def cleanup(self) -> None:
        """清理插件资源"""
        pass

    def is_enabled(self) -> bool:
        """检查插件是否启用"""
        return self.enabled

    def set_enabled(self, enabled: bool) -> None:
        """设置插件启用状态"""
        self.enabled = enabled


class BaseVulnerabilityDetector(BasePlugin, IVulnerabilityDetector):
    """漏洞检测器插件基类"""

    def __init__(self):
        super().__init__()
        self.plugin_type = "detector"

    @abstractmethod
    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        """检测漏洞"""
        pass

    def get_detector_info(self) -> Dict[str, Any]:
        """获取检测器信息"""
        return {
            "name": self.metadata.name,
            "version": self.metadata.version,
            "description": self.metadata.description,
            "plugin_type": self.plugin_type
        }


class BaseReportGeneratorPlugin(BasePlugin, IReportGenerator):
    """报告生成器插件基类"""

    def __init__(self):
        super().__init__()
        self.plugin_type = "reporter"

    @abstractmethod
    def generate_console_report(self, results: Dict[str, Any]) -> None:
        """生成控制台报告"""
        pass

    @abstractmethod
    def generate_markdown_report(self, results: Dict[str, Any], output_path: str) -> None:
        """生成Markdown报告"""
        pass


class BaseAnalyzerPlugin(BasePlugin, ICodeAnalyzer):
    """分析器插件基类"""

    def __init__(self):
        super().__init__()
        self.plugin_type = "analyzer"

    @abstractmethod
    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """分析文件"""
        pass

    async def analyze_batch(self, file_paths: List[Path], severity_filter: SeverityLevel) -> List[AnalysisResult]:
        """批量分析文件"""
        results = []
        for file_path in file_paths:
            result = await self.analyze_file(file_path, severity_filter)
            results.append(result)
        return results

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        return {
            "name": self.metadata.name,
            "version": self.metadata.version,
            "description": self.metadata.description,
            "plugin_type": self.plugin_type
        }


class IPluginManager(Protocol):
    """插件管理器接口"""

    def load_plugins(self, plugin_dir: str) -> None:
        """加载插件"""
        pass

    def get_detector_plugins(self) -> List[IVulnerabilityDetector]:
        """获取检测器插件"""
        pass

    def get_reporter_plugins(self) -> List[IReportGenerator]:
        """获取报告生成器插件"""
        pass

    def get_analyzer_plugins(self) -> List[ICodeAnalyzer]:
        """获取分析器插件"""
        pass

    def register_plugin(self, plugin: BasePlugin) -> None:
        """注册插件"""
        pass

    def enable_plugin(self, plugin_name: str) -> bool:
        """启用插件"""
        pass

    def disable_plugin(self, plugin_name: str) -> bool:
        """禁用插件"""
        pass

    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """获取插件信息"""
        pass

    def list_plugins(self) -> List[Dict[str, Any]]:
        """列出所有插件"""
        pass


class DynamicPluginManager(IPluginManager):
    """动态插件管理器"""

    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self.detector_plugins: List[IVulnerabilityDetector] = []
        self.reporter_plugins: List[IReportGenerator] = []
        self.analyzer_plugins: List[ICodeAnalyzer] = []
        self.loaded_modules: Dict[str, Any] = {}

    def load_plugins(self, plugin_dir: str) -> None:
        """从指定目录动态加载插件"""
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            logger.warning(f"插件目录不存在: {plugin_path}")
            return

        logger.info(f"开始加载插件,目录：{plugin_path}")

        # 查找所有Python文件
        plugin_files = list(plugin_path.glob("*.py"))
        plugin_files.extend(list(plugin_path.glob("plugin_*.py")))

        loaded_count = 0
        for plugin_file in plugin_files:
            if plugin_file.name.startswith("__"):
                continue

            try:
                plugin = self._load_plugin_from_file(plugin_file)
                if plugin:
                    self.register_plugin(plugin)
                    loaded_count += 1
                    logger.info(f"插件加载成功: {plugin.metadata.name} v{plugin.metadata.version}")

            except Exception as e:
                logger.error(f"插件加载失败 {plugin_file}: {e}")

        logger.info(f"插件加载完成,共加载 {loaded_count} 个插件")

    def _load_plugin_from_file(self, plugin_file: Path) -> Optional[BasePlugin]:
        """从文件加载插件"""
        try:
            # 动态导入模块
            spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 查找插件类
            plugin_classes = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BasePlugin) and
                    obj != BasePlugin and
                    obj != BaseVulnerabilityDetector and
                    obj != BaseReportGeneratorPlugin and
                    obj != BaseAnalyzerPlugin):
                    plugin_classes.append(obj)

            if not plugin_classes:
                logger.warning(f"在 {plugin_file} 中未找到插件类")
                return None

            # 实例化第一个插件类
            plugin_class = plugin_classes[0]
            plugin_instance = plugin_class()

            return plugin_instance

        except Exception as e:
            logger.error(f"加载插件文件失败 {plugin_file}: {e}")
            return None

    def register_plugin(self, plugin: BasePlugin) -> None:
        """注册插件"""
        plugin_name = plugin.metadata.name
        self.plugins[plugin_name] = plugin

        # 根据插件类型添加到相应的列表
        if isinstance(plugin, IVulnerabilityDetector):
            self.detector_plugins.append(plugin)
        elif isinstance(plugin, IReportGenerator):
            self.reporter_plugins.append(plugin)
        elif isinstance(plugin, ICodeAnalyzer):
            self.analyzer_plugins.append(plugin)

        logger.debug(f"插件注册成功: {plugin_name}")

    def get_detector_plugins(self) -> List[IVulnerabilityDetector]:
        """获取启用的检测器插件"""
        return [p for p in self.detector_plugins if p.is_enabled()]

    def get_reporter_plugins(self) -> List[IReportGenerator]:
        """获取启用的报告生成器插件"""
        return [p for p in self.reporter_plugins if p.is_enabled()]

    def get_analyzer_plugins(self) -> List[ICodeAnalyzer]:
        """获取启用的分析器插件"""
        return [p for p in self.analyzer_plugins if p.is_enabled()]

    def enable_plugin(self, plugin_name: str) -> bool:
        """启用插件"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].set_enabled(True)
            logger.info(f"插件已启用: {plugin_name}")
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """禁用插件"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].set_enabled(False)
            logger.info(f"插件已禁用: {plugin_name}")
            return True
        return False

    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """获取插件信息"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            info = plugin.metadata.to_dict()
            info["enabled"] = plugin.is_enabled()
            return info
        return None

    def list_plugins(self) -> List[Dict[str, Any]]:
        """列出所有插件"""
        plugin_list = []
        for plugin_name, plugin in self.plugins.items():
            info = plugin.metadata.to_dict()
            info["enabled"] = plugin.is_enabled()
            plugin_list.append(info)
        return plugin_list

    def initialize_plugins(self) -> bool:
        """初始化所有插件"""
        success_count = 0
        total_count = len(self.plugins)

        for plugin_name, plugin in self.plugins.items():
            try:
                if plugin.initialize():
                    success_count += 1
                    logger.debug(f"插件初始化成功: {plugin_name}")
                else:
                    logger.warning(f"插件初始化失败: {plugin_name}")
            except Exception as e:
                logger.error(f"插件初始化异常 {plugin_name}: {e}")
                plugin.set_enabled(False)

        logger.info(f"插件初始化完成: {success_count}/{total_count} 成功")
        return success_count > 0

    def cleanup_plugins(self) -> None:
        """清理插件资源"""
        for plugin_name, plugin in self.plugins.items():
            try:
                plugin.cleanup()
                logger.debug(f"插件清理完成: {plugin_name}")
            except Exception as e:
                logger.error(f"插件清理异常 {plugin_name}: {e}")

    def get_plugin_statistics(self) -> Dict[str, Any]:
        """获取插件统计信息"""
        total_plugins = len(self.plugins)
        enabled_plugins = sum(1 for p in self.plugins.values() if p.is_enabled())
        detector_count = len(self.detector_plugins)
        reporter_count = len(self.reporter_plugins)
        analyzer_count = len(self.analyzer_plugins)

        return {
            "total_plugins": total_plugins,
            "enabled_plugins": enabled_plugins,
            "disabled_plugins": total_plugins - enabled_plugins,
            "detector_plugins": detector_count,
            "reporter_plugins": reporter_count,
            "analyzer_plugins": analyzer_count,
            "plugin_types": {
                "detector": len([p for p in self.plugins.values() if p.metadata.plugin_type == "detector"]),
                "reporter": len([p for p in self.plugins.values() if p.metadata.plugin_type == "reporter"]),
                "analyzer": len([p for p in self.plugins.values() if p.metadata.plugin_type == "analyzer"])
            }
        }


# 示例插件实现
class ExampleSQLInjectionDetector(BaseVulnerabilityDetector):
    """示例SQL注入检测器插件"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ExampleSQLInjectionDetector",
            version="1.0.0",
            description="示例SQL注入检测器插件",
            author="CodeSentinel Team",
            plugin_type="detector"
        )

    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        """检测SQL注入漏洞"""
        import re
        vulnerabilities = []
        lines = content.split('\n')

        dangerous_patterns = [
            (r'execute\s*\([^)]*\+[^)]*\)', 'SQL字符串拼接'),
            (r'execute\s*\([^)]*%[^)]*\)', 'SQL字符串格式化')
        ]

        for i, line in enumerate(lines, 1):
            for pattern, description in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerability = Vulnerability(
                        type="SQL注入(插件检测)",
                        severity=SeverityLevel.HIGH,
                        line=i,
                        description=f"检测到{description},可能导致SQL注入",
                        remediation="使用参数化查询替代字符串拼接",
                        code_snippet=line.strip()[:100],
                        confidence=0.8
                    )
                    vulnerabilities.append(vulnerability)
                    break

        return vulnerabilities


class ExampleCustomReportGenerator(BaseReportGeneratorPlugin):
    """示例自定义报告生成器插件"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ExampleCustomReportGenerator",
            version="1.0.0",
            description="示例自定义报告生成器插件",
            author="CodeSentinel Team",
            plugin_type="reporter"
        )

    def generate_console_report(self, results: Dict[str, Any]) -> None:
        """生成自定义控制台报告"""
        print("=== 自定义报告 ===")
        print(f"发现 {results.get('total_vulnerabilities', 0)} 个漏洞")
        print("=== 报告结束 ===")

    def generate_markdown_report(self, results: Dict[str, Any], output_path: str) -> None:
        """生成自定义Markdown报告"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# 自定义安全报告\n\n")
            f.write(f"发现 {results.get('total_vulnerabilities', 0)} 个漏洞\n")


# 插件工厂
class PluginFactory:
    """插件工厂"""

    @staticmethod
    def create_plugin_manager() -> IPluginManager:
        """创建插件管理器"""
        return DynamicPluginManager()

    @staticmethod
    def create_example_plugins() -> List[BasePlugin]:
        """创建示例插件"""
        return [
            ExampleSQLInjectionDetector(),
            ExampleCustomReportGenerator()
        ]

    @staticmethod
    def get_plugin_types() -> Dict[str, Type[BasePlugin]]:
        """获取支持的插件类型"""
        return {
            "detector": BaseVulnerabilityDetector,
            "reporter": BaseReportGeneratorPlugin,
            "analyzer": BaseAnalyzerPlugin
        }