#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UI界面管理器
提供专业的启动界面、图标显示和视觉元素
"""

import os
import sys
import time
import threading
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path
import asyncio

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# 图标和符号定义
ICONS = {
    'shield': '🛡️',
    'lock': '🔒',
    'search': '🔍',
    'warning': '⚠️',
    'error': '❌',
    'success': '✅',
    'info': 'ℹ️',
    'rocket': '🚀',
    'star': '⭐',
    'fire': '🔥',
    'crystal': '💎',
    'ai': '🤖',
    'code': '💻',
    'security': '🔐',
    'scan': '📡',
    'target': '🎯',
    'lightning': '⚡',
    'pulse': '💓',
    'wave': '〰️',
    'orbit': '🔮'
}

# 颜色定义
if COLORAMA_AVAILABLE:
    COLORS = {
        'primary': Fore.CYAN,
        'secondary': Fore.MAGENTA,
        'success': Fore.GREEN,
        'warning': Fore.YELLOW,
        'error': Fore.RED,
        'info': Fore.BLUE,
        'muted': Fore.WHITE,
        'bright': Style.BRIGHT,
        'reset': Style.RESET_ALL
    }
else:
    COLORS = {k: '' for k in ['primary', 'secondary', 'success', 'warning', 'error', 'info', 'muted', 'bright', 'reset']}


class UIManager:
    """UI界面管理器"""

    def __init__(self):
        self.animation_active = False
        self.animation_thread = None
        self.terminal_width = self._get_terminal_width()

    def _get_terminal_width(self) -> int:
        """获取终端宽度"""
        try:
            return os.get_terminal_size().columns
        except:
            return 80

    def _center_text(self, text: str, width: Optional[int] = None) -> str:
        """居中文本"""
        if width is None:
            width = self.terminal_width
        return text.center(width)

    def _print_banner_line(self, char: str = '═', color: str = 'primary') -> None:
        """打印横幅线条"""
        line = char * self.terminal_width
        print(f"{COLORS[color]}{line}{COLORS['reset']}")

    def show_startup_screen(self, version: str = "2.0.0") -> None:
        """显示启动界面"""
        self.clear_screen()

        # 顶部装饰
        print("\n" * 2)
        self._print_banner_line('╔═', 'primary')

        # 主标题区域
        title_lines = [
            f"{ICONS['shield']}  CodeSentinel AI Security Audit  {ICONS['shield']}",
            f"{ICONS['ai']}  Intelligent Code Security Analysis  {ICONS['ai']}",
            f"Version {version} • AI-Powered Security Scanning"
        ]

        for line in title_lines:
            print(f"{COLORS['primary']}{self._center_text(line)}{COLORS['reset']}")

        self._print_banner_line('╠═', 'secondary')

        # 特性展示
        features = [
            ("AI + AST Hybrid Analysis", ICONS['crystal']),
            ("Real-time Vulnerability Detection", ICONS['target']),
            ("Enterprise-grade Security Scanning", ICONS['security']),
            ("Multi-format Report Generation", ICONS['code'])
        ]

        print(f"{COLORS['secondary']}{self._center_text('✨ Core Features ✨')}{COLORS['reset']}")
        print()

        for feature, icon in features:
            feature_text = f"{icon} {feature}"
            print(f"{COLORS['info']}{self._center_text(feature_text)}{COLORS['reset']}")

        self._print_banner_line('╠═', 'secondary')

        # 状态信息
        status_info = [
            ("Initializing Security Engine...", ICONS['pulse']),
            ("Loading AI Models...", ICONS['ai']),
            ("Preparing Analysis Modules...", ICONS['orbit'])
        ]

        print()
        for info, icon in status_info:
            status_text = f"{icon} {info}"
            print(f"{COLORS['muted']}{self._center_text(status_text)}{COLORS['reset']}")

        self._print_banner_line('╚═', 'primary')
        print("\n")

    def show_loading_animation(self, message: str = "Initializing", duration: float = 2.0) -> None:
        """显示加载动画"""
        self.animation_active = True

        def animate():
            animation_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            i = 0
            start_time = time.time()

            while self.animation_active and (time.time() - start_time) < duration:
                char = animation_chars[i % len(animation_chars)]
                status = f"\r{COLORS['primary']}{char} {message}...{COLORS['reset']}"
                print(status, end='', flush=True)
                time.sleep(0.1)
                i += 1

            print(f"\r{COLORS['success']}{ICONS['success']} {message} Complete!{COLORS['reset']}")

        self.animation_thread = threading.Thread(target=animate)
        self.animation_thread.start()

        # 等待动画完成
        if self.animation_thread:
            self.animation_thread.join(timeout=duration + 0.5)

        self.animation_active = False

    def show_logo_animation(self) -> None:
        """显示Logo动画"""
        logo_frames = [
            f"{ICONS['shield']} {ICONS['ai']} {ICONS['shield']}",
            f"{ICONS['ai']} {ICONS['shield']} {ICONS['ai']}",
            f"{ICONS['shield']} {ICONS['crystal']} {ICONS['shield']}",
            f"{ICONS['ai']} {ICONS['crystal']} {ICONS['ai']}"
        ]

        print(f"\n{COLORS['primary']}{self._center_text('CodeSentinel')}{COLORS['reset']}")

        for i, frame in enumerate(logo_frames * 2):  # 播放两次
            color = 'primary' if i % 2 == 0 else 'secondary'
            print(f"\r{COLORS[color]}{self._center_text(frame)}{COLORS['reset']}", end='')
            time.sleep(0.3)
        print()  # 换行

    def show_security_badge(self, score: int) -> None:
        """显示安全评分徽章"""
        if score >= 90:
            badge = f"{ICONS['shield']} SECURE {ICONS['shield']}"
            color = 'success'
        elif score >= 70:
            badge = f"{ICONS['warning']} CAUTION {ICONS['warning']}"
            color = 'warning'
        else:
            badge = f"{ICONS['error']} VULNERABLE {ICONS['error']}"
            color = 'error'

        badge_text = f"Security Score: {score}/100 {badge}"
        print(f"\n{COLORS[color]}{self._center_text(badge_text)}{COLORS['reset']}")

    def show_progress_bar(self, current: int, total: int, message: str = "Progress") -> None:
        """显示进度条"""
        if total == 0:
            return

        percentage = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)

        progress_text = f"{message}: [{bar}] {percentage:.1f}% ({current}/{total})"
        print(f"\r{COLORS['info']}{progress_text}{COLORS['reset']}", end='', flush=True)

        if current == total:
            print()  # 完成时换行

    def show_status_panel(self, status_data: Dict[str, Any]) -> None:
        """显示状态面板"""
        print(f"\n{COLORS['secondary']}{'═' * self.terminal_width}{COLORS['reset']}")
        print(f"{COLORS['primary']}{self._center_text('System Status')}{COLORS['reset']}")
        print(f"{COLORS['secondary']}{'─' * self.terminal_width}{COLORS['reset']}")

        for key, value in status_data.items():
            status_line = f"{ICONS['info']} {key}: {value}"
            print(f"{COLORS['info']}{status_line}{COLORS['reset']}")

        print(f"{COLORS['secondary']}{'═' * self.terminal_width}{COLORS['reset']}")

    def show_mini_dashboard(self, stats: Dict[str, int]) -> None:
        """显示迷你仪表板"""
        print(f"\n{COLORS['primary']}{'┌' + '─' * (self.terminal_width - 2) + '┐'}{COLORS['reset']}")
        print(f"{COLORS['primary']}│{COLORS['reset']}{self._center_text('Quick Stats', self.terminal_width - 2)}{COLORS['primary']}│{COLORS['reset']}")
        print(f"{COLORS['primary']}{'├' + '─' * (self.terminal_width - 2) + '┤'}{COLORS['reset']}")

        # 显示统计信息
        for key, value in stats.items():
            stat_text = f"{ICONS['star']} {key}: {value}"
            padding = self.terminal_width - len(stat_text) - 2
            print(f"{COLORS['primary']}│{COLORS['reset']}{stat_text}{' ' * padding}{COLORS['primary']}│{COLORS['reset']}")

        print(f"{COLORS['primary']}{'└' + '─' * (self.terminal_width - 2) + '┘'}{COLORS['reset']}")

    def show_ai_thinking_animation(self, duration: float = 1.5) -> None:
        """显示AI思考动画"""
        thinking_texts = [
            "AI is analyzing code patterns...",
            "Searching for security vulnerabilities...",
            "Applying machine learning models...",
            "Cross-referencing vulnerability databases...",
            "Generating security recommendations..."
        ]

        start_time = time.time()
        i = 0

        while time.time() - start_time < duration:
            text = thinking_texts[i % len(thinking_texts)]
            dots = '.' * ((i % 4) + 1)

            thinking_display = f"{ICONS['ai']} {text}{dots}"
            print(f"\r{COLORS['secondary']}{thinking_display}{' ' * 10}{COLORS['reset']}", end='', flush=True)

            time.sleep(0.5)
            i += 1

        print(f"\r{COLORS['success']}{ICONS['success']} AI Analysis Complete!{COLORS['reset']}")

    def show_scanning_visualization(self, file_count: int) -> None:
        """显示扫描可视化"""
        print(f"\n{COLORS['primary']}{self._center_text('🔍 Initiating Security Scan 🔍')}{COLORS['reset']}")

        # 扫描波效果
        scan_chars = ['◐', '◓', '◑', '◒']

        for i in range(min(file_count, 20)):  # 最多显示20个文件的扫描
            scan_char = scan_chars[i % len(scan_chars)]
            file_text = f"Scanning file {i+1}/{file_count}"

            wave_effect = ''.join(['〰️' if j % 2 == 0 else '〜' for j in range(10)])

            scan_line = f"{scan_char} {file_text} {wave_effect}"
            print(f"\r{COLORS['info']}{scan_line}{COLORS['reset']}", end='', flush=True)
            time.sleep(0.1)

        print(f"\n{COLORS['success']}{ICONS['success']} Scan Complete!{COLORS['reset']}")

    def clear_screen(self) -> None:
        """清屏"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_error_screen(self, error_message: str, error_id: str) -> None:
        """显示错误界面"""
        print(f"\n{COLORS['error']}{'=' * self.terminal_width}{COLORS['reset']}")
        print(f"{COLORS['error']}{self._center_text(f'{ICONS['error']} SECURITY SCAN ERROR {ICONS['error']}')}{COLORS['reset']}")
        print(f"{COLORS['error']}{'=' * self.terminal_width}{COLORS['reset']}")

        print(f"\n{COLORS['error']}Error Message:{COLORS['reset']}")
        print(f"{COLORS['muted']}{error_message}{COLORS['reset']}")

        print(f"\n{COLORS['error']}Error ID: {error_id}{COLORS['reset']}")

        print(f"\n{COLORS['warning']}Troubleshooting:{COLORS['reset']}")
        print(f"{COLORS['info']}1. Check the error message above{COLORS['reset']}")
        print(f"{COLORS['info']}2. Verify your configuration files{COLORS['reset']}")
        print(f"{COLORS['info']}3. Ensure all dependencies are installed{COLORS['reset']}")
        print(f"{COLORS['info']}4. Check the log file for more details{COLORS['reset']}")

        print(f"\n{COLORS['error']}{'=' * self.terminal_width}{COLORS['reset']}")

    def show_success_screen(self, summary: Dict[str, Any]) -> None:
        """显示成功完成界面"""
        print(f"\n{COLORS['success']}{'=' * self.terminal_width}{COLORS['reset']}")
        print(f"{COLORS['success']}{self._center_text(f'{ICONS['success']} SECURITY SCAN COMPLETE {ICONS['success']}')}{COLORS['reset']}")
        print(f"{COLORS['success']}{'=' * self.terminal_width}{COLORS['reset']}")

        # 显示摘要信息
        if summary:
            print(f"\n{COLORS['primary']}Scan Summary:{COLORS['reset']}")
            for key, value in summary.items():
                print(f"{ICONS['star']} {key}: {value}")

        print(f"\n{COLORS['success']}{self._center_text('Your code has been analyzed successfully!')}{COLORS['reset']}")
        print(f"{COLORS['success']}{'=' * self.terminal_width}{COLORS['reset']}")


# 全局UI管理器实例
ui_manager = UIManager()


def show_startup_banner(version: str = "2.0.0") -> None:
    """显示启动横幅（便捷函数）"""
    ui_manager.show_startup_screen(version)


def show_loading(message: str = "Loading", duration: float = 2.0) -> None:
    """显示加载动画（便捷函数）"""
    ui_manager.show_loading_animation(message, duration)


def clear_terminal() -> None:
    """清屏（便捷函数）"""
    ui_manager.clear_screen()