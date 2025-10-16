#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
监控和指标收集模块
提供性能监控、指标收集和健康检查功能
"""

import asyncio
import time
import logging
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json
import psutil

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """性能指标数据类"""
    # 分析相关指标
    total_files_analyzed: int = 0
    total_analysis_time: float = 0.0
    average_analysis_time: float = 0.0
    files_per_second: float = 0.0

    # AI调用指标
    ai_api_calls: int = 0
    ai_api_errors: int = 0
    ai_api_success_rate: float = 100.0
    ai_average_response_time: float = 0.0

    # 缓存指标
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_rate: float = 0.0
    cache_size: int = 0

    # 系统资源指标
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    disk_usage_mb: float = 0.0

    # 时间戳
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class MetricsCollector:
    """指标收集器"""

    def __init__(self):
        self._metrics = PerformanceMetrics()
        self._ai_response_times: List[float] = []
        self._analysis_times: List[float] = []
        self._lock = threading.Lock()
        self._start_time = time.time()

    def record_file_analysis(self, analysis_time: float, file_size: int) -> None:
        """记录文件分析"""
        with self._lock:
            self._analysis_times.append(analysis_time)
            self._metrics.total_files_analyzed += 1
            self._metrics.total_analysis_time += analysis_time

            # 计算平均分析时间
            if self._analysis_times:
                self._metrics.average_analysis_time = sum(self._analysis_times) / len(self._analysis_times)
                self._metrics.files_per_second = 1.0 / self._metrics.average_analysis_time if self._metrics.average_analysis_time > 0 else 0.0

    def record_ai_api_call(self, response_time: float, success: bool) -> None:
        """记录AI API调用"""
        with self._lock:
            self._ai_response_times.append(response_time)
            self._metrics.ai_api_calls += 1

            if not success:
                self._metrics.ai_api_errors += 1

            # 计算成功率
            if self._metrics.ai_api_calls > 0:
                self._metrics.ai_api_success_rate = ((self._metrics.ai_api_calls - self._metrics.ai_api_errors) / self._metrics.ai_api_calls) * 100.0

            # 计算平均响应时间
            if self._ai_response_times:
                self._metrics.ai_average_response_time = sum(self._ai_response_times) / len(self._ai_response_times)

    def record_cache_operation(self, hit: bool) -> None:
        """记录缓存操作"""
        with self._lock:
            if hit:
                self._metrics.cache_hits += 1
            else:
                self._metrics.cache_misses += 1

            # 计算缓存命中率
            total_cache_ops = self._metrics.cache_hits + self._metrics.cache_misses
            if total_cache_ops > 0:
                self._metrics.cache_hit_rate = (self._metrics.cache_hits / total_cache_ops) * 100.0

    def update_system_metrics(self) -> None:
        """更新系统资源使用指标"""
        try:
            # 获取内存使用情况
            memory_info = psutil.virtual_memory()
            self._metrics.memory_usage_mb = memory_info.used / (1024 * 1024)

            # 获取CPU使用率
            self._metrics.cpu_usage_percent = psutil.cpu_percent(interval=0.1)

            # 获取磁盘使用情况
            disk_info = psutil.disk_usage('.')
            self._metrics.disk_usage_mb = (disk_info.total - disk_info.free) / (1024 * 1024)

        except Exception as e:
            logger.warning(f"更新系统指标失败: {e}")

    def get_metrics(self) -> PerformanceMetrics:
        """获取当前指标"""
        self.update_system_metrics()
        self._metrics.timestamp = datetime.now().isoformat()
        return self._metrics

    def reset_metrics(self) -> None:
        """重置指标"""
        with self._lock:
            self._metrics = PerformanceMetrics()
            self._ai_response_times.clear()
            self._analysis_times.clear()
            self._start_time = time.time()

    def get_uptime_seconds(self) -> float:
        """获取运行时间"""
        return time.time() - self._start_time


class HealthChecker:
    """健康检查器"""

    def __init__(self):
        self._health_status: Dict[str, Any] = {
            "status": "healthy",
            "checks": {},
            "timestamp": datetime.now().isoformat()
        }
        self._check_functions: Dict[str, callable] = {}

    def register_check(self, name: str, check_func: callable) -> None:
        """注册健康检查函数"""
        self._check_functions[name] = check_func

    async def run_health_checks(self) -> Dict[str, Any]:
        """运行所有健康检查"""
        overall_status = "healthy"
        checks = {}

        for name, check_func in self._check_functions.items():
            try:
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()

                checks[name] = result

                # 如果有任何检查失败,整体状态为不健康
                if result.get("status") != "healthy":
                    overall_status = "unhealthy"

            except Exception as e:
                checks[name] = {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                overall_status = "unhealthy"

        self._health_status = {
            "status": overall_status,
            "checks": checks,
            "timestamp": datetime.now().isoformat()
        }

        return self._health_status

    def get_health_status(self) -> Dict[str, Any]:
        """获取健康状态"""
        return self._health_status


class MonitoringService:
    """监控服务主类"""

    def __init__(self, metrics_file: Optional[str] = None):
        self.metrics_collector = MetricsCollector()
        self.health_checker = HealthChecker()
        self.metrics_file = Path(metrics_file) if metrics_file else None
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()

        # 注册默认健康检查
        self._register_default_health_checks()

    def _register_default_health_checks(self) -> None:
        """注册默认健康检查"""

        def check_disk_space():
            """检查磁盘空间"""
            try:
                disk_info = psutil.disk_usage('.')
                free_percent = (disk_info.free / disk_info.total) * 100

                if free_percent < 10:
                    status = "unhealthy"
                    message = f"磁盘空间不足,仅剩 {free_percent:.1f}%"
                elif free_percent < 20:
                    status = "warning"
                    message = f"磁盘空间偏低,剩余 {free_percent:.1f}%"
                else:
                    status = "healthy"
                    message = f"磁盘空间充足,剩余 {free_percent:.1f}%"

                return {
                    "status": status,
                    "message": message,
                    "free_percent": free_percent,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"磁盘检查失败: {e}",
                    "timestamp": datetime.now().isoformat()
                }

        def check_memory_usage():
            """检查内存使用"""
            try:
                memory_info = psutil.virtual_memory()

                if memory_info.percent > 90:
                    status = "unhealthy"
                    message = f"内存使用过高：{memory_info.percent:.1f}%"
                elif memory_info.percent > 80:
                    status = "warning"
                    message = f"内存使用偏高：{memory_info.percent:.1f}%"
                else:
                    status = "healthy"
                    message = f"内存使用正常：{memory_info.percent:.1f}%"

                return {
                    "status": status,
                    "message": message,
                    "memory_percent": memory_info.percent,
                    "available_mb": memory_info.available / (1024 * 1024),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"内存检查失败: {e}",
                    "timestamp": datetime.now().isoformat()
                }

        self.health_checker.register_check("disk_space", check_disk_space)
        self.health_checker.register_check("memory_usage", check_memory_usage)

    def start_monitoring(self, interval: int = 60) -> None:
        """开始监控"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            logger.warning("监控已经在运行中")
            return

        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self._monitoring_thread.start()
        logger.info(f"监控服务启动,更新间隔：{interval}秒")

    def stop_monitoring(self) -> None:
        """停止监控"""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=5)
            logger.info("监控服务已停止")

    def _monitoring_loop(self, interval: int) -> None:
        """监控循环"""
        while not self._stop_monitoring.is_set():
            try:
                # 更新系统指标
                self.metrics_collector.update_system_metrics()

                # 保存指标到文件
                if self.metrics_file:
                    self.save_metrics_to_file()

                logger.debug("监控指标已更新")

            except Exception as e:
                logger.error(f"监控循环出错: {e}")

            # 等待下一次更新
            self._stop_monitoring.wait(interval)

    def save_metrics_to_file(self) -> None:
        """保存指标到文件"""
        if not self.metrics_file:
            return

        try:
            metrics = self.metrics_collector.get_metrics()
            metrics_dict = {
                "metrics": metrics.__dict__,
                "uptime_seconds": self.metrics_collector.get_uptime_seconds(),
                "export_timestamp": datetime.now().isoformat()
            }

            # 确保目录存在
            self.metrics_file.parent.mkdir(parents=True, exist_ok=True)

            # 写入临时文件然后原子重命名
            temp_file = self.metrics_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(metrics_dict, f, indent=2, ensure_ascii=False)

            temp_file.replace(self.metrics_file)

        except Exception as e:
            logger.error(f"保存监控指标失败: {e}")

    def get_monitoring_report(self) -> Dict[str, Any]:
        """获取监控报告"""
        metrics = self.metrics_collector.get_metrics()
        health = self.health_checker.get_health_status()

        return {
            "metrics": metrics.__dict__,
            "health": health,
            "uptime_seconds": self.metrics_collector.get_uptime_seconds(),
            "report_timestamp": datetime.now().isoformat()
        }


# 全局监控服务实例
_monitoring_service: Optional[MonitoringService] = None


def init_monitoring(metrics_file: Optional[str] = None) -> MonitoringService:
    """初始化监控服务"""
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = MonitoringService(metrics_file)
    return _monitoring_service


def get_monitoring() -> Optional[MonitoringService]:
    """获取监控服务实例"""
    return _monitoring_service


def cleanup_monitoring() -> None:
    """清理监控服务"""
    global _monitoring_service
    if _monitoring_service:
        _monitoring_service.stop_monitoring()
        _monitoring_service = None
