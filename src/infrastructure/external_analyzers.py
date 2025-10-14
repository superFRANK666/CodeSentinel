#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外部分析器调用模块
负责调用外部工具进行代码分析，如ESLint等
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..core.interfaces import Vulnerability, SeverityLevel

logger = logging.getLogger(__name__)


class ExternalAnalyzerError(Exception):
    """外部分析器异常"""
    pass


def run_eslint_analysis(file_path: Path) -> List[Vulnerability]:
    """
    运行ESLint分析JavaScript文件

    Args:
        file_path: JavaScript文件路径

    Returns:
        List[Vulnerability]: 发现的漏洞列表

    Raises:
        ExternalAnalyzerError: 当ESLint不可用或分析失败时
    """
    logger.info(f"开始对文件 {file_path} 进行ESLint分析")

    # 验证文件存在性
    if not file_path.exists():
        logger.error(f"文件不存在: {file_path}")
        raise ExternalAnalyzerError(f"文件不存在: {file_path}")

    # 验证文件大小（避免分析过大文件）
    file_size = file_path.stat().st_size
    if file_size > 10 * 1024 * 1024:  # 10MB限制
        logger.warning(f"文件过大，跳过分析: {file_path} ({file_size} bytes)")
        raise ExternalAnalyzerError(f"文件过大: {file_path} ({file_size} bytes)")

    temp_report_path = None
    try:
        # 创建临时报告文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_report_path = temp_file.name

        # 构建ESLint命令
        eslint_cmd = [
            'eslint',
            '--format', 'json',
            '--output-file', temp_report_path,
            '--no-eslintrc',  # 忽略用户配置，使用项目配置
            '--config', str(Path(__file__).parent.parent.parent / '.eslintrc.json'),
            str(file_path)
        ]

        logger.debug(f"执行ESLint命令: {' '.join(eslint_cmd)}")

        # 执行ESLint
        result = subprocess.run(
            eslint_cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5分钟超时
        )

        # 检查执行结果
        if result.returncode not in [0, 1]:  # ESLint返回0表示无问题，1表示发现问题
            logger.error(f"ESLint执行失败: {result.stderr}")
            raise ExternalAnalyzerError(f"ESLint执行失败: {result.stderr}")

        # 读取JSON报告
        vulnerabilities = []
        if Path(temp_report_path).exists():
            with open(temp_report_path, 'r', encoding='utf-8') as f:
                eslint_results = json.load(f)

            # 转换ESLint结果为Vulnerability对象
            vulnerabilities = _convert_eslint_results(eslint_results, file_path)
        else:
            logger.warning(f"ESLint报告文件不存在: {temp_report_path}")
            vulnerabilities = []

        logger.info(f"ESLint分析完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    except subprocess.TimeoutExpired:
        logger.error(f"ESLint分析超时: {file_path}")
        raise ExternalAnalyzerError("ESLint分析超时")

    except FileNotFoundError:
        logger.error("ESLint未安装或不可用")
        raise ExternalAnalyzerError(
            "ESLint未安装或不可用。请安装ESLint: npm install -g eslint eslint-plugin-security"
        )

    except json.JSONDecodeError as e:
        logger.error(f"解析ESLint JSON报告失败: {e}")
        raise ExternalAnalyzerError(f"解析ESLint报告失败: {e}")

    except Exception as e:
        logger.error(f"ESLint分析过程中发生错误: {e}")
        raise ExternalAnalyzerError(f"ESLint分析失败: {e}")

    finally:
        # 确保清理临时文件
        if temp_report_path and Path(temp_report_path).exists():
            try:
                Path(temp_report_path).unlink()
                logger.debug(f"已清理临时文件: {temp_report_path}")
            except Exception as e:
                logger.warning(f"清理临时文件失败: {e}")


def _convert_eslint_results(eslint_results: List[Dict], file_path: Path) -> List[Vulnerability]:
    """
    将ESLint结果转换为Vulnerability对象

    Args:
        eslint_results: ESLint输出的JSON结果
        file_path: 分析的文件路径

    Returns:
        List[Vulnerability]: 转换后的漏洞列表
    """
    vulnerabilities = []

    for file_result in eslint_results:
        if not file_result.get('messages'):
            continue

        file_path_str = file_result.get('filePath', str(file_path))

        for message in file_result.get('messages', []):
            # 获取漏洞信息
            rule_id = message.get('ruleId', 'unknown')
            severity = message.get('severity', 1)  # 1=warning, 2=error
            line = message.get('line', 0)
            column = message.get('column', 0)
            message_text = message.get('message', '')

            # 转换严重程度
            if severity == 2:
                severity_level = SeverityLevel.HIGH
            elif severity == 1:
                severity_level = SeverityLevel.MEDIUM
            else:
                severity_level = SeverityLevel.LOW

            # 安全相关的规则提升严重程度
            if _is_security_rule(rule_id):
                if severity_level == SeverityLevel.MEDIUM:
                    severity_level = SeverityLevel.HIGH
                elif severity_level == SeverityLevel.LOW:
                    severity_level = SeverityLevel.MEDIUM

            # 创建漏洞对象
            vulnerability = Vulnerability(
                type=rule_id,
                severity=severity_level,
                line=line,
                description=message_text,
                remediation=_get_remediation_for_rule(rule_id),
                code_snippet=_extract_code_snippet(file_path, line),
                confidence=0.9,  # ESLint置信度较高
                cwe_id=_get_cwe_for_rule(rule_id),
                owasp_category=_get_owasp_category_for_rule(rule_id)
            )

            vulnerabilities.append(vulnerability)

    return vulnerabilities


def _is_security_rule(rule_id: str) -> bool:
    """判断是否为安全相关规则"""
    security_rules = [
        'security/detect-eval-with-expression',
        'security/detect-no-csrf-before-method-override',
        'security/detect-non-literal-fs-filename',
        'security/detect-non-literal-regexp',
        'security/detect-non-literal-require',
        'security/detect-object-injection',
        'security/detect-possible-timing-attacks',
        'security/detect-pseudoRandomBytes',
        'no-eval',
        'no-implied-eval',
        'no-new-func',
        'no-script-url'
    ]
    return rule_id in security_rules


def _get_remediation_for_rule(rule_id: str) -> str:
    """获取规则的修复建议"""
    remediation_map = {
        'security/detect-eval-with-expression': '避免使用eval()函数，使用JSON.parse()或其他安全的替代方案',
        'security/detect-no-csrf-before-method-override': '在方法重写之前添加CSRF保护',
        'security/detect-non-literal-fs-filename': '验证和清理文件名，避免路径遍历攻击',
        'security/detect-non-literal-regexp': '避免使用动态正则表达式，或进行严格的输入验证',
        'security/detect-non-literal-require': '验证模块路径，避免任意代码执行',
        'security/detect-object-injection': '避免将用户输入直接用作对象属性名',
        'security/detect-possible-timing-attacks': '使用恒定时间比较函数避免时序攻击',
        'security/detect-pseudoRandomBytes': '使用加密安全的随机数生成器',
        'no-eval': '避免使用eval()，使用更安全的替代方案如JSON.parse()',
        'no-implied-eval': '避免使用setTimeout/setInterval的字符串参数形式',
        'no-new-func': '避免使用Function构造函数，使用函数声明或箭头函数',
        'no-script-url': '避免使用javascript: URL，使用事件处理器代替'
    }

    return remediation_map.get(rule_id, '请参考ESLint文档获取具体的修复建议')


def _get_cwe_for_rule(rule_id: str) -> Optional[str]:
    """获取规则对应的CWE编号"""
    cwe_map = {
        'security/detect-eval-with-expression': 'CWE-94',
        'security/detect-non-literal-fs-filename': 'CWE-22',
        'security/detect-non-literal-require': 'CWE-94',
        'security/detect-object-injection': 'CWE-94',
        'security/detect-possible-timing-attacks': 'CWE-208',
        'security/detect-pseudoRandomBytes': 'CWE-338',
        'no-eval': 'CWE-94',
        'no-implied-eval': 'CWE-94',
        'no-new-func': 'CWE-94',
        'no-script-url': 'CWE-79'
    }

    return cwe_map.get(rule_id)


def _get_owasp_category_for_rule(rule_id: str) -> Optional[str]:
    """获取规则对应的OWASP分类"""
    owasp_map = {
        'security/detect-eval-with-expression': 'A03:2021 – Injection',
        'security/detect-non-literal-fs-filename': 'A01:2021 – Broken Access Control',
        'security/detect-non-literal-require': 'A03:2021 – Injection',
        'security/detect-object-injection': 'A03:2021 – Injection',
        'security/detect-possible-timing-attacks': 'A02:2021 – Cryptographic Failures',
        'security/detect-pseudoRandomBytes': 'A02:2021 – Cryptographic Failures',
        'no-eval': 'A03:2021 – Injection',
        'no-implied-eval': 'A03:2021 – Injection',
        'no-new-func': 'A03:2021 – Injection',
        'no-script-url': 'A03:2021 – Injection'
    }

    return owasp_map.get(rule_id)


def _extract_code_snippet(file_path: Path, line_number: int, context_lines: int = 3) -> str:
    """
    从文件中提取代码片段

    Args:
        file_path: 文件路径
        line_number: 目标行号
        context_lines: 上下文行数

    Returns:
        str: 代码片段
    """
    try:
        if not file_path.exists():
            return f"文件不存在: {file_path}"

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        start_line = max(0, line_number - 1 - context_lines)
        end_line = min(len(lines), line_number + context_lines)

        snippet_lines = []
        for i in range(start_line, end_line):
            line_indicator = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{line_indicator}{i+1:4d}: {lines[i].rstrip()}")

        return "\n".join(snippet_lines)

    except Exception as e:
        logger.warning(f"提取代码片段失败: {e}")
        return f"无法提取代码片段: {str(e)}"


def check_eslint_availability() -> bool:
    """
    检查ESLint是否可用

    Returns:
        bool: ESLint是否可用
    """
    try:
        result = subprocess.run(
            ['eslint', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_eslint_version() -> Optional[str]:
    """
    获取ESLint版本信息

    Returns:
        Optional[str]: ESLint版本，如果不可用则返回None
    """
    try:
        result = subprocess.run(
            ['eslint', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def install_eslint_dependencies():
    """
    提供ESLint依赖安装指导
    """
    print("\n📦 ESLint依赖安装指导:")
    print("=" * 50)
    print("1. 确保已安装Node.js (https://nodejs.org/)")
    print("   node --version  # 检查Node.js版本")
    print("   npm --version   # 检查npm版本")
    print("\n2. 全局安装ESLint:")
    print("   npm install -g eslint")
    print("\n3. 安装安全插件:")
    print("   npm install -g eslint-plugin-security")
    print("\n4. 验证安装:")
    print("   eslint --version")
    print("\n5. 测试配置:")
    print("   eslint --init  # 可选：创建ESLint配置文件")
    print("=" * 50)


def validate_eslint_setup() -> Dict[str, Any]:
    """
    验证ESLint设置

    Returns:
        Dict[str, Any]: 验证结果
    """
    result = {
        'eslint_available': False,
        'version': None,
        'security_plugin_available': False,
        'config_available': False,
        'recommendations': []
    }

    # 检查ESLint可用性
    if check_eslint_availability():
        result['eslint_available'] = True
        result['version'] = get_eslint_version()
        result['recommendations'].append("✅ ESLint已安装")
    else:
        result['recommendations'].append("❌ ESLint未安装")
        result['recommendations'].append("请运行: npm install -g eslint")
        return result

    # 检查配置文件
    config_paths = [
        Path('.eslintrc.json'),
        Path('.eslintrc.js'),
        Path('.eslintrc.yml'),
        Path('.eslintrc.yaml')
    ]

    for config_path in config_paths:
        if config_path.exists():
            result['config_available'] = True
            result['recommendations'].append(f"✅ 找到ESLint配置: {config_path}")
            break

    if not result['config_available']:
        result['recommendations'].append("⚠️  未找到ESLint配置文件")
        result['recommendations'].append("建议创建.eslintrc.json配置文件")

    return result