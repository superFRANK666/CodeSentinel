#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASCII艺术和图标模块
提供各种ASCII艺术字体和图标
"""
import time

# CodeSentinel ASCII艺术字体
CODESENTINEL_LOGO = r"""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║    ██████╗ ██████╗  ██████╗ ███████╗███████╗██╗██╗     ███████╗    ║
    ║    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██║██║     ██╔════╝    ║
    ║    ██████╔╝██████╔╝██║   ██║███████╗███████╗██║██║     █████╗      ║
    ║    ██╔═══╝ ██╔══██╗██║   ██║╚════██║╚════██║██║██║     ██╔══╝      ║
    ║    ██║     ██║  ██║╚██████╔╝███████║███████║██║███████╗███████╗    ║
    ║    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝╚══════╝╚══════╝    ║
    ║                                                                       ║
    ║              AI-Powered Code Security Analysis Platform               ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
"""

# 简化的Logo
SIMPLE_LOGO = r"""
     ╔═══════════════════════════════════════╗
     ║                                       ║
     ║     🛡️  CodeSentinel Security  🛡️     ║
     ║         AI Code Analysis Platform     ║
     ║                                       ║
     ╚═══════════════════════════════════════╝
"""

# 图标集合
SECURITY_ICONS = {
    "shield_large": r"""
         ████████████
       ████████████████
     ████████████████████
   ████████████████████████
  ██████████████████████████
 ████████████████████████████
████████████████████████████████
████████████████████████████████
████████████████████████████████
████████████████████████████████
 ████████████████████████████
  ██████████████████████████
   ████████████████████████
     ████████████████████
       ████████████████
         ████████████
    """,
    "crystal": r"""
        💎
       ╱╲╱╲
      ╱  ╲  ╱
     ╱    ╲╱
    ╱╲    ╱
   ╱  ╲  ╱
  ╱    ╲╱
 ╱╲    ╱
╱  ╲  ╱
    ╲╱
    """,
    "ai_brain": r"""
    ╔═══════════════════════╗
    ║  ╭─────────────────╮  ║
    ║  │  🧠 AI BRAIN 🧠  │  ║
    ║  │   Neural Net    │  ║
    ║  │  █ █ █ █ █ █ █  │  ║
    ║  │  █ █ █ █ █ █ █  │  ║
    ║  │  █ █ █ █ █ █ █  │  ║
    ║  ╰─────────────────╯  ║
    ╚═══════════════════════╝
    """,
    "security_wall": r"""
    ╔═══════════════════════════════════════╗
    ║  🛡️ SECURITY WALL 🛡️                ║
    ║  ┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐  ║
    ║  │█││█││█││█││█││█││█││█││█││█│  ║
    ║  └─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘  ║
    ║  ┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐  ║
    ║  │█││█││█││█││█││█││█││█││█││█│  ║
    ║  └─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘  ║
    ╚═══════════════════════════════════════╝
    """,
}

# 扫描动画帧
SCAN_ANIMATION_FRAMES = [
    r"""
     ╭─────────────────╮
     │  🔍 SCANNING 🔍 │
     │     ◐ ○ ○       │
     ╰─────────────────╯
    """,
    r"""
     ╭─────────────────╮
     │  🔍 SCANNING 🔍 │
     │     ○ ◐ ○       │
     ╰─────────────────╯
    """,
    r"""
     ╭─────────────────╮
     │  🔍 SCANNING 🔍 │
     │     ○ ○ ◐       │
     ╰─────────────────╯
    """,
    r"""
     ╭─────────────────╮
     │  🔍 SCANNING 🔍 │
     │     ○ ◐ ○       │
     ╰─────────────────╯
    """,
]

# AI思考动画
AI_THINKING_FRAMES = [
    r"""
     ╔═══════════════════════╗
     ║  🤔 AI THINKING...    ║
     ║    ● ○ ○              ║
     ║   Neural Processing   ║
     ╚═══════════════════════╝
    """,
    r"""
     ╔═══════════════════════╗
     ║  🤔 AI THINKING...    ║
     ║    ○ ● ○              ║
     ║   Neural Processing   ║
     ╚═══════════════════════╝
    """,
    r"""
     ╔═══════════════════════╗
     ║  🤔 AI THINKING...    ║
     ║    ○ ○ ●              ║
     ║   Neural Processing   ║
     ╚═══════════════════════╝
    """,
]

# 进度条样式
PROGRESS_BARS = {
    "modern": {"empty": "░", "filled": "▓", "left": "▌", "right": "▐"},
    "classic": {"empty": " ", "filled": "█", "left": "[", "right": "]"},
    "unicode": {"empty": "▁", "filled": "█", "left": "╾", "right": "╼"},
}

# 装饰性边框
BORDERS = {
    "double": {
        "horizontal": "═",
        "vertical": "║",
        "top_left": "╔",
        "top_right": "╗",
        "bottom_left": "╚",
        "bottom_right": "╝",
        "left_t": "╠",
        "right_t": "╣",
        "top_t": "╦",
        "bottom_t": "╩",
        "cross": "╬",
    },
    "single": {
        "horizontal": "─",
        "vertical": "│",
        "top_left": "┌",
        "top_right": "┐",
        "bottom_left": "└",
        "bottom_right": "┘",
        "left_t": "├",
        "right_t": "┤",
        "top_t": "┬",
        "bottom_t": "┴",
        "cross": "┼",
    },
    "thick": {
        "horizontal": "━",
        "vertical": "┃",
        "top_left": "┏",
        "top_right": "┓",
        "bottom_left": "┗",
        "bottom_right": "┛",
        "left_t": "┣",
        "right_t": "┫",
        "top_t": "┳",
        "bottom_t": "┻",
        "cross": "╋",
    },
}

# 状态图标
STATUS_ICONS = {
    "success": "✅",
    "error": "❌",
    "warning": "⚠️",
    "info": "ℹ️",
    "loading": "⏳",
    "complete": "✨",
    "scan": "🔍",
    "security": "🛡️",
    "ai": "🤖",
    "code": "💻",
    "vulnerability": "🐛",
    "fixed": "🔧",
    "critical": "🚨",
    "high": "🔴",
    "medium": "🟡",
    "low": "🟢",
}

# 渐变色文本（使用ANSI转义序列）
GRADIENT_COLORS = [
    "\033[38;5;51m",  # 青色
    "\033[38;5;50m",
    "\033[38;5;49m",
    "\033[38;5;48m",
    "\033[38;5;47m",
    "\033[38;5;46m",
    "\033[38;5;82m",
    "\033[38;5;118m",
    "\033[38;5;154m",
    "\033[38;5;190m",
    "\033[38;5;226m",  # 黄色
]


def create_gradient_text(text: str) -> str:
    """创建渐变色文本"""
    result = ""
    for i, char in enumerate(text):
        if char != " ":
            color_index = i % len(GRADIENT_COLORS)
            result += f"{GRADIENT_COLORS[color_index]}{char}\033[0m"
        else:
            result += char
    return result


def create_rainbow_text(text: str) -> str:
    """创建彩虹色文本"""
    rainbow_colors = [
        "\033[91m",  # 红色
        "\033[93m",  # 黄色
        "\033[92m",  # 绿色
        "\033[96m",  # 青色
        "\033[94m",  # 蓝色
        "\033[95m",  # 紫色
    ]

    result = ""
    for i, char in enumerate(text):
        if char != " ":
            color_index = i % len(rainbow_colors)
            result += f"{rainbow_colors[color_index]}{char}\033[0m"
        else:
            result += char
    return result


def create_border(width: int, border_style: str = "double", title: str = "") -> str:
    """创建边框"""
    border = BORDERS[border_style]

    if title:
        title_padding = (width - len(title) - 4) // 2
        right_padding = width - len(title) - 4 - title_padding
        top_line = (
            f"{border['top_left']}{border['horizontal'] * title_padding} "
            f"{title} {border['horizontal'] * right_padding}{border['top_right']}"
        )
    else:
        top_line = f"{border['top_left']}{border['horizontal'] * (width - 2)}{border['top_right']}"

    bottom_line = f"{border['bottom_left']}{border['horizontal'] * (width - 2)}{border['bottom_right']}"

    return f"{top_line}\n{{content}}\n{bottom_line}"


def create_progress_bar(percentage: float, width: int = 40, style: str = "modern") -> str:
    """创建进度条"""
    pb = PROGRESS_BARS[style]
    filled_length = int(width * percentage / 100)
    empty_length = width - filled_length

    bar = pb["filled"] * filled_length + pb["empty"] * empty_length
    return f"{pb['left']}{bar}{pb['right']} {percentage:.1f}%"


# 动画效果类
class AnimationEffects:
    """动画效果类"""

    @staticmethod
    def typing_effect(text: str, delay: float = 0.05) -> None:
        """打字机效果"""
        for char in text:
            print(char, end="", flush=True)
            time.sleep(delay)
        print()

    @staticmethod
    def blink_effect(text: str, duration: float = 2.0) -> None:
        """闪烁效果"""
        start_time = time.time()
        while time.time() - start_time < duration:
            print(f"\r{text}", end="", flush=True)
            time.sleep(0.5)
            print(f"\r{' ' * len(text)}", end="", flush=True)
            time.sleep(0.5)
        print()

    @staticmethod
    def wave_effect(text: str) -> None:
        """波浪效果"""
        for i in range(len(text)):
            wave_char = "〰️" if i % 2 == 0 else "〜"
            print(f"\r{text[:i]}{wave_char}{text[i + 1:]}", end="", flush=True)
            time.sleep(0.1)
        print()


# 导出常用的艺术字体和图标
__all__ = [
    "CODESENTINEL_LOGO",
    "SIMPLE_LOGO",
    "SECURITY_ICONS",
    "SCAN_ANIMATION_FRAMES",
    "AI_THINKING_FRAMES",
    "PROGRESS_BARS",
    "BORDERS",
    "STATUS_ICONS",
    "GRADIENT_COLORS",
    "create_gradient_text",
    "create_rainbow_text",
    "create_border",
    "create_progress_bar",
    "AnimationEffects",
]
