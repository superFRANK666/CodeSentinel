#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
错误处理器实现模块
提供友好的错误信息和解决方案建议
"""

import traceback
import logging
from typing import Dict, Any, List
from ..core.interfaces import IErrorHandler


logger = logging.getLogger(__name__)


class FriendlyErrorHandler(IErrorHandler):
    """友好的错误处理器"""

    def __init__(self):
        self.error_suggestions = {
            # API相关错误
            "openai.AuthenticationError": {
                "message": "OpenAI API认证失败",
                "suggestions": [
                    "请检查您的OPENAI_API_KEY是否正确设置",
                    "访问 https://platform.openai.com/api-keys 获取有效的API密钥",
                    "确保API密钥没有过期或被撤销",
                    "检查环境变量设置是否正确（set OPENAI_API_KEY=your-key）"
                ],
                "severity": "high"
            },
            "openai.RateLimitError": {
                "message": "OpenAI API请求频率超限",
                "suggestions": [
                    "您当前的API调用频率超过了限制",
                    "请稍后再试,或减少并发请求数量",
                    "考虑升级到更高级别的API套餐",
                    "使用本地分析器替代AI分析"
                ],
                "severity": "medium"
            },
            "openai.APIConnectionError": {
                "message": "无法连接到OpenAI API服务",
                "suggestions": [
                    "请检查您的网络连接是否正常",
                    "确认能够访问 https://api.openai.com",
                    "检查防火墙或代理设置是否阻止了连接",
                    "尝试使用不同的网络环境",
                    "使用离线分析模式"
                ],
                "severity": "high"
            },
            "openai.APITimeoutError": {
                "message": "OpenAI API请求超时",
                "suggestions": [
                    "API响应时间过长,请稍后重试",
                    "检查网络连接稳定性",
                    "增加REQUEST_TIMEOUT环境变量的值",
                    "减少分析文件的大小或复杂度",
                    "使用本地分析器替代"
                ],
                "severity": "medium"
            },

            # 文件相关错误
            "FileNotFoundError": {
                "message": "文件或目录不存在",
                "suggestions": [
                    "请检查文件路径是否正确",
                    "确认文件是否存在于指定位置",
                    "使用绝对路径而非相对路径",
                    "检查文件权限是否允许读取"
                ],
                "severity": "medium"
            },
            "PermissionError": {
                "message": "文件权限不足",
                "suggestions": [
                    "请检查文件读取权限",
                    "以管理员身份运行程序",
                    "修改文件权限（chmod 755 filename）",
                    "将文件复制到具有权限的目录"
                ],
                "severity": "medium"
            },
            "UnicodeDecodeError": {
                "message": "文件编码错误",
                "suggestions": [
                    "文件可能使用了非UTF-8编码",
                    "尝试指定文件编码参数",
                    "使用文本编辑器将文件转换为UTF-8编码",
                    "检查文件是否包含二进制数据"
                ],
                "severity": "low"
            },

            # 配置相关错误
            "ValueError": {
                "message": "配置值无效",
                "suggestions": [
                    "请检查配置文件格式是否正确",
                    "确认配置参数值在有效范围内",
                    "参考文档中的配置示例",
                    "使用默认配置进行测试"
                ],
                "severity": "medium"
            },
            "KeyError": {
                "message": "配置项缺失",
                "suggestions": [
                    "请检查配置文件是否完整",
                    "确认所有必需的配置项都已设置",
                    "使用默认配置文件作为模板",
                    "查看配置文档了解必需的配置项"
                ],
                "severity": "medium"
            },

            # 内存和资源错误
            "MemoryError": {
                "message": "内存不足",
                "suggestions": [
                    "文件可能过大,超出了系统内存限制",
                    "尝试分析较小的文件或分批处理",
                    "增加系统虚拟内存",
                    "关闭其他占用内存的程序",
                    "使用流式分析而非全文件加载"
                ],
                "severity": "high"
            },

            # 依赖相关错误
            "ImportError": {
                "message": "缺少必需的依赖库",
                "suggestions": [
                    "请安装缺失的Python包",
                    "运行: pip install -r requirements.txt",
                    "检查Python环境是否正确",
                    "确认依赖库版本兼容性"
                ],
                "severity": "high"
            },
            "ModuleNotFoundError": {
                "message": "找不到指定的模块",
                "suggestions": [
                    "请安装所需的Python模块",
                    "运行: pip install 模块名",
                    "检查模块名称是否拼写正确",
                    "确认模块是否在Python路径中"
                ],
                "severity": "high"
            },

            # 网络相关错误
            "ConnectionError": {
                "message": "网络连接错误",
                "suggestions": [
                    "请检查网络连接是否正常",
                    "确认目标服务器是否可访问",
                    "检查防火墙和代理设置",
                    "尝试使用离线模式"
                ],
                "severity": "high"
            },
            "TimeoutError": {
                "message": "网络请求超时",
                "suggestions": [
                    "网络连接超时,请检查网络稳定性",
                    "增加超时时间设置",
                    "尝试减少并发请求数量",
                    "检查目标服务器响应时间"
                ],
                "severity": "medium"
            },

            # 通用错误
            "Exception": {
                "message": "发生未知错误",
                "suggestions": [
                    "请查看详细的错误信息",
                    "检查日志文件获取更多上下文",
                    "尝试重新运行程序",
                    "如果问题持续,请报告此错误"
                ],
                "severity": "low"
            }
        }

    def handle_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """处理错误并返回友好的错误信息"""
        error_type = type(error).__name__
        error_message = str(error)

        # 获取错误类型对应的建议
        error_info = self._get_error_info(error_type, error_message)

        # 生成详细的错误报告
        error_report = {
            "error_type": error_type,
            "error_message": error_message,
            "friendly_message": error_info["message"],
            "suggestions": error_info["suggestions"],
            "severity": error_info["severity"],
            "context": context,
            "timestamp": self._get_timestamp(),
            "error_id": self._generate_error_id()
        }

        # 添加技术详情（调试用）
        if context.get('debug_mode', False):
            error_report["technical_details"] = {
                "traceback": traceback.format_exc(),
                "error_args": getattr(error, 'args', []),
                "error_cause": getattr(error, '__cause__', None),
                "error_context": getattr(error, '__context__', None)
            }

        # 记录错误日志
        self._log_error(error_report, error)

        return error_report

    def get_error_suggestions(self, error_type: str) -> List[str]:
        """获取错误解决建议"""
        error_info = self.error_suggestions.get(error_type, self.error_suggestions["Exception"])
        return error_info["suggestions"]

    def _get_error_info(self, error_type: str, error_message: str) -> Dict[str, Any]:
        """获取错误信息"""
        # 首先尝试精确匹配
        if error_type in self.error_suggestions:
            return self.error_suggestions[error_type]

        # 尝试基于错误消息内容匹配
        for known_error, info in self.error_suggestions.items():
            if known_error.lower() in error_message.lower():
                return info

        # 返回通用错误信息
        return self.error_suggestions["Exception"]

    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()

    def _generate_error_id(self) -> str:
        """生成错误ID"""
        import uuid
        return str(uuid.uuid4())[:8]

    def _log_error(self, error_report: Dict[str, Any], original_error: Exception) -> None:
        """记录错误日志"""
        severity = error_report["severity"]

        if severity == "high":
            logger.error(f"严重错误 [{error_report['error_id']}]: {error_report['error_message']}")
        elif severity == "medium":
            logger.warning(f"警告 [{error_report['error_id']}]: {error_report['error_message']}")
        else:
            logger.info(f"信息 [{error_report['error_id']}]: {error_report['error_message']}")

        # 记录调试信息
        if error_report.get("technical_details"):
            logger.debug(f"技术详情 [{error_report['error_id']}]: {error_report['technical_details']}")

    def add_custom_error_handler(self, error_type: str, message: str,
                               suggestions: List[str], severity: str = "medium") -> None:
        """添加自定义错误处理器"""
        self.error_suggestions[error_type] = {
            "message": message,
            "suggestions": suggestions,
            "severity": severity
        }

    def get_error_statistics(self) -> Dict[str, Any]:
        """获取错误统计信息"""
        # 这里可以实现错误统计功能
        return {
            "total_error_types": len(self.error_suggestions),
            "error_categories": {
                "api_errors": len([k for k in self.error_suggestions.keys() if "openai" in k.lower()]),
                "file_errors": len([k for k in self.error_suggestions.keys() if "file" in k.lower()]),
                "config_errors": len([k for k in self.error_suggestions.keys() if "config" in k.lower()]),
                "network_errors": len([k for k in self.error_suggestions.keys() if "connection" in k.lower() or "timeout" in k.lower()])
            }
        }


class DetailedErrorHandler(FriendlyErrorHandler):
    """详细的错误处理器 - 提供技术细节"""

    def handle_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """处理错误并返回详细信息"""
        basic_report = super().handle_error(error, context)

        # 添加详细的技术信息
        detailed_info = {
            "error_class": error.__class__.__module__ + "." + error.__class__.__name__,
            "error_module": error.__class__.__module__,
            "error_doc": error.__class__.__doc__,
            "stack_trace": traceback.format_exc(),
            "local_variables": self._get_local_variables(),
            "system_info": self._get_system_info()
        }

        basic_report["detailed_info"] = detailed_info
        return basic_report

    def _get_local_variables(self) -> Dict[str, Any]:
        """获取局部变量信息"""
        import inspect
        frame = inspect.currentframe()
        try:
            # 获取调用者的局部变量
            caller_frame = frame.f_back
            if caller_frame:
                local_vars = {}
                for key, value in caller_frame.f_locals.items():
                    if not key.startswith('__'):
                        try:
                            local_vars[key] = str(type(value))
                        except Exception:
                            local_vars[key] = "<无法序列化>"
                return local_vars
        finally:
            del frame
        return {}

    def _get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        import platform
        import sys

        return {
            "platform": platform.platform(),
            "python_version": sys.version,
            "python_executable": sys.executable,
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "memory_info": self._get_memory_info()
        }

    def _get_memory_info(self) -> Dict[str, Any]:
        """获取内存信息"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": str(e)}


class ContextualErrorHandler(FriendlyErrorHandler):
    """上下文感知的错误处理器"""

    def handle_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """根据上下文处理错误"""
        basic_report = super().handle_error(error, context)

        # 根据上下文添加特定的建议
        contextual_suggestions = self._get_contextual_suggestions(error, context)
        basic_report["contextual_suggestions"] = contextual_suggestions

        return basic_report

    def _get_contextual_suggestions(self, error: Exception, context: Dict[str, Any]) -> List[str]:
        """获取上下文相关的建议"""
        suggestions = []

        # 根据分析阶段提供建议
        analysis_phase = context.get('analysis_phase')
        if analysis_phase == 'file_reading':
            suggestions.append("检查文件路径和权限")
            suggestions.append("确认文件编码格式")
        elif analysis_phase == 'ai_analysis':
            suggestions.append("检查API密钥和网络连接")
            suggestions.append("考虑使用本地分析模式")
        elif analysis_phase == 'report_generation':
            suggestions.append("检查输出目录权限")
            suggestions.append("确认磁盘空间充足")

        # 根据文件类型提供建议
        file_type = context.get('file_type')
        if file_type:
            suggestions.append(f"确保{file_type}文件格式正确")

        # 根据错误频率提供建议
        error_frequency = context.get('error_frequency', 0)
        if error_frequency > 3:
            suggestions.append("该错误频繁出现,建议检查配置或数据源")
            suggestions.append("考虑使用更稳定的分析模式")

        return suggestions


def create_error_handler(handler_type: str = "friendly", **kwargs) -> IErrorHandler:
    """创建错误处理器工厂函数"""
    if handler_type == "friendly":
        return FriendlyErrorHandler(**kwargs)
    elif handler_type == "detailed":
        return DetailedErrorHandler(**kwargs)
    elif handler_type == "contextual":
        return ContextualErrorHandler(**kwargs)
    else:
        raise ValueError(f"不支持的错误处理器类型: {handler_type}")