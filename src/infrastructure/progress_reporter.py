#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进度报告器实现模块
提供多种进度显示方式,包括控制台进度条和日志进度
"""

import logging
import sys
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core.interfaces import IProgressReporter

logger = logging.getLogger(__name__)


class BaseProgressReporter(IProgressReporter, ABC):
    """进度报告器基类 - 增强版本"""

    def __init__(self):
        self.total = 0
        self.current = 0
        self.description = ""
        self.start_time = 0
        self._finished = False
        # 增强功能
        self._subtasks: List[Dict[str, Any]] = []
        self._current_subtask = 0
        self._checkpoint_times: Dict[str, float] = {}
        self._last_update_time = 0
        self._min_update_interval = 0.1  # 最小更新间隔(秒)
        self._progress_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._eta_samples: List[float] = []  # 用于更准确的ETA计算
        self._max_eta_samples = 10

    def start_progress(self, total: int, description: str = "") -> None:
        """开始进度报告 - 增强版本"""
        with self._lock:
            self.total = total
            self.current = 0
            self.description = description
            self.start_time = time.time()
            self._finished = False
            self._subtasks.clear()
            self._current_subtask = 0
            self._checkpoint_times.clear()
            self._last_update_time = 0
            self._progress_history.clear()
            self._eta_samples.clear()

            # 记录开始事件
            self._record_progress_event("start", description)
            self._on_start()

    def update_progress(self, current: int, message: str = "") -> None:
        """更新进度 - 增强版本"""
        current_time = time.time()

        with self._lock:
            # 检查更新间隔,避免过于频繁的更新
            if current_time - self._last_update_time < self._min_update_interval:
                return

            self.current = current
            self._last_update_time = current_time

            # 记录进度历史用于分析
            self._record_progress_event("update", message, current)

            # 更新ETA样本
            if current > 0:
                elapsed = current_time - self.start_time
                if elapsed > 0:
                    rate = current / elapsed
                    if rate > 0:
                        remaining = self.total - current
                        eta = remaining / rate
                        self._eta_samples.append(eta)
                        # 保持样本数量在合理范围
                        if len(self._eta_samples) > self._max_eta_samples:
                            self._eta_samples.pop(0)

            self._on_update(message)

    def finish_progress(self) -> None:
        """完成进度 - 增强版本"""
        with self._lock:
            if self._finished:
                return

            self._finished = True
            self.current = self.total

            # 记录完成事件
            self._record_progress_event("finish", "完成")
            self._on_finish()

    def add_subtask(self, name: str, total: int, description: str = "") -> None:
        """添加子任务"""
        with self._lock:
            subtask = {
                "name": name,
                "total": total,
                "current": 0,
                "description": description,
                "start_time": time.time(),
                "status": "pending",
            }
            self._subtasks.append(subtask)

    def update_subtask(self, subtask_name: str, current: int, message: str = "") -> None:
        """更新子任务进度"""
        with self._lock:
            for subtask in self._subtasks:
                if subtask["name"] == subtask_name:
                    subtask["current"] = current
                    subtask["status"] = "running"
                    if message:
                        subtask["description"] = message
                    break

    def complete_subtask(self, subtask_name: str, message: str = "") -> None:
        """完成子任务"""
        with self._lock:
            for subtask in self._subtasks:
                if subtask["name"] == subtask_name:
                    subtask["current"] = subtask["total"]
                    subtask["status"] = "completed"
                    if message:
                        subtask["description"] = message
                    break

    def set_checkpoint(self, name: str) -> None:
        """设置检查点"""
        with self._lock:
            self._checkpoint_times[name] = time.time()

    def get_checkpoint_time(self, name: str) -> float:
        """获取检查点用时"""
        with self._lock:
            if name in self._checkpoint_times:
                return time.time() - self._checkpoint_times[name]
            return 0.0

    def get_enhanced_progress_info(self) -> Dict[str, Any]:
        """获取增强的进度信息"""
        with self._lock:
            elapsed_time = self.get_elapsed_time()
            progress_percent = self.get_progress_percentage()

            # 计算增强版ETA
            if self._eta_samples and progress_percent > 10:  # 至少10%进度才开始计算ETA
                avg_eta = sum(self._eta_samples) / len(self._eta_samples)
                eta = avg_eta
            else:
                eta = self.get_estimated_time_remaining()

            # 计算处理速度
            processing_rate = 0.0
            if elapsed_time > 0 and self.current > 0:
                processing_rate = self.current / elapsed_time

            return {
                "current": self.current,
                "total": self.total,
                "percentage": progress_percent,
                "elapsed_seconds": elapsed_time,
                "eta_seconds": eta,
                "processing_rate": processing_rate,
                "description": self.description,
                "subtasks": self._subtasks.copy(),
                "is_finished": self._finished,
                "last_update_time": self._last_update_time,
            }

    def _record_progress_event(self, event_type: str, message: str, current: Optional[int] = None) -> None:
        """记录进度事件"""
        event = {
            "type": event_type,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "progress": current if current is not None else self.current,
            "total": self.total,
        }
        self._progress_history.append(event)

        # 限制历史记录大小
        if len(self._progress_history) > 1000:
            self._progress_history.pop(0)

    def increment(self, step: int = 1, message: str = "") -> None:
        """递增进度"""
        self.update_progress(self.current + step, message)

    def get_progress_percentage(self) -> float:
        """获取进度百分比"""
        if self.total <= 0:
            return 0.0
        return min(100.0, (self.current / self.total) * 100)

    def get_elapsed_time(self) -> float:
        """获取已用时间"""
        return time.time() - self.start_time

    def get_estimated_time_remaining(self) -> float:
        """获取预计剩余时间"""
        if self.current <= 0 or self.total <= 0:
            return 0.0

        elapsed = self.get_elapsed_time()
        rate = self.current / elapsed
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else 0.0

    @abstractmethod
    def _on_start(self) -> None:
        """进度开始时的回调"""
        pass

    @abstractmethod
    def _on_update(self, message: str = "") -> None:
        """进度更新时的回调"""
        pass

    @abstractmethod
    def _on_finish(self) -> None:
        """进度完成时的回调"""
        pass


class TqdmProgressReporter(BaseProgressReporter):
    """基于tqdm的进度报告器"""

    def __init__(self, disable: bool = False):
        super().__init__()
        self.disable = disable
        self._progress_bar = None

        try:
            from tqdm import tqdm

            self.tqdm = tqdm
        except ImportError:
            # 如果tqdm不可用,降级到简单进度报告器
            self.disable = True

    def _on_start(self) -> None:
        """进度开始时的回调"""
        if self.disable:
            if self.description:
                print(f"开始: {self.description}")
            return

        try:
            self._progress_bar = self.tqdm(
                total=self.total, desc=self.description, unit="文件", leave=True, file=sys.stdout
            )
        except Exception:
            self.disable = True
            if self.description:
                print(f"开始: {self.description}")

    def _on_update(self, message: str = "") -> None:
        """进度更新时的回调 - 增强版本"""
        if self.disable:
            if message and self.current % max(1, self.total // 10) == 0:
                percentage = self.get_progress_percentage()
                eta = self.get_estimated_time_remaining()
                eta_str = self._format_time(eta)
                print(f"进度: {percentage:.1f}% - {message} (预计剩余: {eta_str})")
            return

        if self._progress_bar:
            try:
                self._progress_bar.update(self.current - self._progress_bar.n)

                # 增强进度条显示信息
                if message:
                    # 计算处理速度和ETA
                    elapsed = self.get_elapsed_time()
                    if elapsed > 0 and self.current > 0:
                        rate = self.current / elapsed
                        eta = self.get_estimated_time_remaining()
                        eta_str = self._format_time(eta)

                        # 创建增强的描述信息
                        enhanced_desc = f"{self.description} - {message}"
                        if rate > 0:
                            enhanced_desc += f" ({rate:.1f} 文件/秒,ETA: {eta_str})"

                        self._progress_bar.set_description(enhanced_desc)
                    else:
                        self._progress_bar.set_description(f"{self.description} - {message}")

                # 更新进度条后缀信息
                if self.current > 0 and self.total > 0:
                    elapsed = self.get_elapsed_time()
                    if elapsed > 0:
                        rate = self.current / elapsed
                        self._progress_bar.set_postfix(
                            {
                                "速度": f"{rate:.1f}文件/秒",
                                "ETA": self._format_time(self.get_estimated_time_remaining()),
                            }
                        )

            except Exception as e:
                logger.debug(f"进度条更新失败: {e}")

    def _format_time(self, seconds: float) -> str:
        """格式化时间显示"""
        if seconds < 60:
            return f"{int(seconds)}秒"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}分{secs}秒"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}小时{minutes}分"

    def _on_finish(self) -> None:
        """进度完成时的回调 - 增强版本"""
        if self.disable:
            elapsed_time = self.get_elapsed_time()
            processing_rate = self.total / elapsed_time if elapsed_time > 0 else 0
            print(
                f"✅ {self.description} 完成 ({self.total}个文件, {elapsed_time:.2f}秒, {processing_rate:.1f}文件/秒)"
            )
            return

        if self._progress_bar:
            try:
                # 显示最终统计信息
                elapsed_time = self.get_elapsed_time()
                processing_rate = self.total / elapsed_time if elapsed_time > 0 else 0

                # 清除当前行并显示完成信息
                self._progress_bar.clear()
                print(f"✅ {self.description} 完成")
                print(f"   📊 处理文件: {self.total}个")
                print(f"   ⏱️  用时: {self._format_time(elapsed_time)}")
                print(f"   ⚡ 处理速度: {processing_rate:.1f}文件/秒")

                self._progress_bar.close()
            except Exception as e:
                logger.debug(f"进度条关闭失败: {e}")
            finally:
                self._progress_bar = None

        # 显示子任务完成情况（如果有）
        if self._subtasks:
            print("\n📋 子任务完成情况:")
            for subtask in self._subtasks:
                status_icon = "✅" if subtask["status"] == "completed" else "❌"
                print(f"   {status_icon} {subtask['name']}: {subtask['description']}")


class SimpleProgressReporter(BaseProgressReporter):
    """简单的控制台进度报告器"""

    def __init__(self, show_percentage: bool = True):
        super().__init__()
        self.show_percentage = show_percentage
        self.last_percentage = -1

    def _on_start(self) -> None:
        """进度开始时的回调"""
        if self.description:
            print(f"🚀 开始: {self.description}")
        print(f"📊 总计: {self.total} 个文件")

    def _on_update(self, message: str = "") -> None:
        """进度更新时的回调"""
        percentage = int(self.get_progress_percentage())

        # 只在百分比变化时更新显示
        if percentage != self.last_percentage and percentage % 10 == 0:
            self.last_percentage = percentage
            remaining = self.get_estimated_time_remaining()

            if self.show_percentage:
                print(f"⏳ 进度: {percentage}% ({self.current}/{self.total})", end="")
                if remaining > 0:
                    print(f" - 预计剩余：{remaining:.1f}秒")
                else:
                    print()
            else:
                print(f"📈 已处理: {self.current}/{self.total}")

        if message:
            print(f"  💡 {message}")

    def _on_finish(self) -> None:
        """进度完成时的回调"""
        elapsed_time = self.get_elapsed_time()
        print(f"✅ 完成: {self.description}")
        print(f"📈 总计: {self.total} 个文件, 用时: {elapsed_time:.2f}秒")
        print(f"⚡ 平均速度：{self.total / elapsed_time:.2f} 文件/秒" if elapsed_time > 0 else "")


class LogProgressReporter(BaseProgressReporter):
    """日志进度报告器"""

    def __init__(self, logger=None):
        super().__init__()
        self.logger = logger

        if self.logger is None:
            import logging

            self.logger = logging.getLogger(__name__)

    def _on_start(self) -> None:
        """进度开始时的回调"""
        self.logger.info(f"开始进度: {self.description}, 总计: {self.total}")

    def _on_update(self, message: str = "") -> None:
        """进度更新时的回调"""
        percentage = self.get_progress_percentage()
        elapsed = self.get_elapsed_time()
        remaining = self.get_estimated_time_remaining()

        log_message = f"进度: {percentage:.1f}% ({self.current}/{self.total}), 已用: {elapsed:.1f}s"
        if remaining > 0:
            log_message += f", 剩余: {remaining:.1f}s"

        self.logger.info(log_message)

        if message:
            self.logger.info(f"详情: {message}")

    def _on_finish(self) -> None:
        """进度完成时的回调"""
        elapsed_time = self.get_elapsed_time()
        self.logger.info(f"进度完成: {self.description}, 总计: {self.total}, 用时: {elapsed_time:.2f}s")


class SilentProgressReporter(BaseProgressReporter):
    """静默进度报告器（用于测试或无界面环境）"""

    def _on_start(self) -> None:
        pass

    def _on_update(self, message: str = "") -> None:
        pass

    def _on_finish(self) -> None:
        pass


# 进度报告器工厂
class ProgressReporterFactory:
    """进度报告器工厂"""

    @staticmethod
    def create_reporter(reporter_type: str = "tqdm", **kwargs) -> IProgressReporter:
        """创建进度报告器实例"""
        if reporter_type.lower() == "tqdm":
            return TqdmProgressReporter(**kwargs)
        elif reporter_type.lower() == "simple":
            return SimpleProgressReporter(**kwargs)
        elif reporter_type.lower() == "log":
            return LogProgressReporter(**kwargs)
        elif reporter_type.lower() == "silent":
            return SilentProgressReporter(**kwargs)
        else:
            raise ValueError(f"Unsupported progress reporter type: {reporter_type}")


def format_time(seconds: float) -> str:
    """格式化时间显示"""
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}分钟"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}小时"
