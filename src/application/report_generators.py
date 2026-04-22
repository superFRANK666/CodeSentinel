#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版报告生成器模块
支持多种输出格式: 控制台、Markdown、JSON、HTML、XML
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List, Optional
from xml.dom import minidom

from ..core.interfaces import (
    IReportGenerator,
    Vulnerability,
    SeverityLevel,
    AnalysisResult,
)


class BaseReportGenerator(IReportGenerator):
    """报告生成器基类"""

    def __init__(self):
        self.severity_colors = {
            "critical": "🔴",
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }
        self.severity_names = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
        }

    def _format_severity(self, severity: SeverityLevel) -> str:
        """格式化严重度显示"""
        emoji = self.severity_colors.get(severity.value, "⚪")
        name = self.severity_names.get(severity.value, severity.value)
        return f"{emoji} {name}"

    def _group_vulnerabilities_by_severity(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, List[Vulnerability]]:
        """按严重度对漏洞进行分组"""
        grouped = {"critical": [], "high": [], "medium": [], "low": []}

        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity in grouped:
                grouped[severity].append(vuln)

        return grouped

    def _calculate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """计算统计信息"""
        summary = results.get("scan_summary", {})
        file_results = results.get("file_results", [])

        total_vulnerabilities = summary.get("total_vulnerabilities", 0)
        severity_counts = summary.get("severity_counts", {})

        # 计算各类漏洞的百分比
        stats = {
            "total_files": summary.get("total_files", 0),
            "total_vulnerabilities": total_vulnerabilities,
            "scan_time": summary.get("scan_time", 0),
            "severity_breakdown": {},
            "risk_assessment": self._assess_risk_level(
                total_vulnerabilities, severity_counts
            ),
            "top_vulnerability_types": self._get_top_vulnerability_types(file_results),
            "files_with_issues": summary.get("files_with_issues", 0),
        }

        # 计算各严重度的百分比
        if total_vulnerabilities > 0:
            for severity, count in severity_counts.items():
                percentage = (count / total_vulnerabilities) * 100
                stats["severity_breakdown"][severity] = {
                    "count": count,
                    "percentage": round(percentage, 1),
                }
        else:
            for severity in ["critical", "high", "medium", "low"]:
                stats["severity_breakdown"][severity] = {"count": 0, "percentage": 0.0}

        return stats

    def _assess_risk_level(
        self, total_vulnerabilities: int, severity_counts: Dict[str, int]
    ) -> str:
        """评估风险等级"""
        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        medium_count = severity_counts.get("medium", 0)

        if critical_count > 0 or high_count >= 5:
            return "极高风险."
        elif high_count > 0 or medium_count >= 10:
            return "高风险."
        elif medium_count > 0 or total_vulnerabilities > 0:
            return "中等风险."
        else:
            return "低风险."

    def _get_top_vulnerability_types(
        self, file_results: List[AnalysisResult]
    ) -> List[Dict[str, Any]]:
        """获取最常见的漏洞类型"""
        vuln_type_counts = {}

        for file_result in file_results:
            for vuln in file_result.vulnerabilities:
                vuln_type_counts[vuln.type] = vuln_type_counts.get(vuln.type, 0) + 1

        # 排序并返回前10种
        sorted_types = sorted(
            vuln_type_counts.items(), key=lambda x: x[1], reverse=True
        )
        return [{"type": vtype, "count": count} for vtype, count in sorted_types[:10]]


class ConsoleReportGenerator(BaseReportGenerator):
    """控制台报告生成器"""

    def generate_report(self, results: Dict[str, Any], output_path: str = None) -> None:
        """生成控制台报告"""
        file_results = results.get("file_results", [])
        stats = self._calculate_statistics(results)

        # 显示扫描摘要
        self._display_scan_summary(stats)

        # 显示详细结果
        if file_results:
            self._display_detailed_results(file_results, stats)
        else:
            print("\n📋 未找到任何安全漏洞！")

        # 显示总结和建议
        self._display_summary_and_recommendations(file_results, stats)

    def _display_scan_summary(self, stats: Dict[str, Any]) -> None:
        """显示扫描摘要"""
        print("\n" + "=" * 60)
        print("🔍 AI代码安全审计报告")
        print("=" * 60)
        print(f"📁 扫描文件数: {stats['total_files']}")
        print(f"⏱️  扫描时间: {stats['scan_time']}秒")
        print(f"🎯 发现漏洞: {stats['total_vulnerabilities']}个")
        print(f"📊 风险等级: {stats['risk_assessment']}")

        if stats["total_vulnerabilities"] > 0:
            print("\n📈 漏洞分布:")
            for severity, info in stats["severity_breakdown"].items():
                if info["count"] > 0:
                    emoji = self.severity_colors.get(severity, "⚪")
                    name = self.severity_names.get(severity, severity)
                    print(
                        f"   {emoji} {name}: {info['count']}个 ({info['percentage']}%) "
                    )

        print("=" * 60)

    def _display_detailed_results(
        self, file_results: List[AnalysisResult], stats: Dict[str, Any]
    ) -> None:
        """显示详细分析结果"""
        for i, file_result in enumerate(file_results, 1):
            self._display_file_result(file_result, i, stats)

    def _display_file_result(
        self, file_result: AnalysisResult, index: int, stats: Dict[str, Any]
    ) -> None:
        """显示单个文件的分析结果"""
        file_path = file_result.file_path
        vulnerabilities = file_result.vulnerabilities
        security_score = file_result.security_score
        status = file_result.analysis_status

        print(f"\n📄 文件 {index}: {file_path}")
        print("-" * 50)

        if status == "error":
            error_msg = (
                file_result.recommendations[0]
                if file_result.recommendations
                else "未知错误"
            )
            print(f"❌ 分析失败: {error_msg}")
            return

        # 显示安全评分
        score_color = self._get_score_color(security_score)
        print(f"🔒 安全评分: {score_color}{security_score}/100")

        if not vulnerabilities:
            print("✅ 未检测到安全漏洞")
            return

        # 按严重度分组显示漏洞
        vuln_by_severity = self._group_vulnerabilities_by_severity(vulnerabilities)

        for severity, vuln_list in vuln_by_severity.items():
            if vuln_list:
                emoji = self.severity_colors.get(severity, "⚪")
                name = self.severity_names.get(severity, severity)
                print(f"\n{emoji} {name}漏洞 ({len(vuln_list)}个):")

                for j, vuln in enumerate(vuln_list, 1):
                    self._display_vulnerability(vuln, j, stats)

    def _display_vulnerability(
        self, vuln: Vulnerability, index: int, stats: Dict[str, Any]
    ) -> None:
        """显示单个漏洞详情"""
        vuln_type = vuln.type
        line = vuln.line
        description = vuln.description
        remediation = vuln.remediation
        code_snippet = vuln.code_snippet
        confidence = vuln.confidence

        print(f"\n   {index}. 【{vuln_type}】第{line}行 (置信度: {confidence:.1%})")
        print(f"      📖 描述: {description}")

        if code_snippet:
            print(
                f"      💻 代码: {code_snippet[:100]}{'...' if len(code_snippet) > 100 else ''}"
            )

        print(f"      🔧 修复: {remediation}")

        if vuln.cwe_id:
            print(f"      📚 CWE: {vuln.cwe_id}")

        if vuln.owasp_category:
            print(f"      🛡️  OWASP: {vuln.owasp_category}")

    def _display_summary_and_recommendations(
        self, file_results: List[AnalysisResult], stats: Dict[str, Any]
    ) -> None:
        """显示总结和建议"""
        all_recommendations = []
        total_vulnerabilities = stats["total_vulnerabilities"]
        files_with_issues = stats["files_with_issues"]

        # 收集所有推荐建议
        for file_result in file_results:
            recommendations = file_result.recommendations
            all_recommendations.extend(recommendations)

        # 显示统计信息
        print("\n" + "=" * 60)
        print("📈 扫描统计")
        print("=" * 60)
        print(f"📁 扫描文件数: {stats['total_files']}")
        print(f"⚠️  问题文件数: {files_with_issues}")
        print(f"🎯 总漏洞数: {total_vulnerabilities}")
        print(f"📊 风险等级: {stats['risk_assessment']}")

        # 显示常见漏洞类型
        if stats["top_vulnerability_types"]:
            print("\n🔍 常见漏洞类型:")
            for i, vuln_type in enumerate(stats["top_vulnerability_types"][:5], 1):
                print(f"   {i}. {vuln_type['type']}: {vuln_type['count']}个")

        # 显示通用建议
        if all_recommendations:
            unique_recommendations = list(set(all_recommendations))
            print(f"\n💡 安全建议 ({len(unique_recommendations)}条):")
            for i, rec in enumerate(unique_recommendations[:10], 1):  # 最多显示10条
                print(f"   {i}. {rec}")

        # 总体评估
        print("\n🎯 整体评估:")
        if total_vulnerabilities == 0:
            print("   ✅ 代码安全性良好，未发现明显漏洞")
        elif stats["risk_assessment"] == "极高风险":
            print("   🚨 发现严重安全问题，需要立即处理")
        elif stats["risk_assessment"] == "高风险":
            print("   ⚠️  发现较多安全问题，需要尽快修复")
        else:
            print("   ℹ️  发现少量安全问题，建议及时修复")

    def _get_score_color(self, score: int) -> str:
        """根据安全评分获取对应的颜色emoji"""
        if score >= 80:
            return "🟢"
        elif score >= 60:
            return "🟡"
        else:
            return "🔴"


class MarkdownReportGenerator(BaseReportGenerator):
    """Markdown报告生成器"""

    def generate_report(
        self, results: Dict[str, Any], output_path: Optional[str] = None
    ) -> None:
        """生成Markdown报告"""
        try:
            stats = self._calculate_statistics(results)
            content = self._build_markdown_content(results, stats)

            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                print(content)

        except Exception as e:
            raise RuntimeError(f"生成Markdown报告失败: {e}.")

    def _build_markdown_content(
        self, results: Dict[str, Any], stats: Dict[str, Any]
    ) -> str:
        """构建Markdown内容"""
        file_results = results.get("file_results", [])
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        content = f"""# 🔍 AI代码安全审计报告

*生成时间: {current_time}*
*分析引擎: {results.get('scan_summary', {}).get('analysis_engine', '混合分析')}*

## 📊 执行摘要

### 扫描统计

| 指标 | 数值 |
|------|------|
| 扫描文件数 | {stats['total_files']} |
| 扫描时间 | {stats['scan_time']}秒 |
| 发现漏洞数 | {stats['total_vulnerabilities']} |
| 风险等级 | {stats['risk_assessment']} |
| 问题文件数 | {stats['files_with_issues']} |

### 漏洞分布

```
严重度分布:
"""

        # 添加漏洞分布图表
        for severity, info in stats["severity_breakdown"].items():
            if info["count"] > 0:
                emoji = self.severity_colors.get(severity, "⚪")
                name = self.severity_names.get(severity, severity)
                bar_length = int(info["percentage"] / 5)
                content += f"{emoji} {name:4} | {'█' * bar_length} {info['percentage']:.1f}% ({info['count']}个)\n"

        content += "```\n\n"

        # 添加常见漏洞类型
        if stats["top_vulnerability_types"]:
            content += "### 🔍 常见漏洞类型\n\n"
            content += "| 排名 | 漏洞类型 | 数量 |\n"
            content += "|------|----------|------|\n"
            for i, vuln_type in enumerate(stats["top_vulnerability_types"][:10], 1):
                content += f"| {i} | {vuln_type['type']} | {vuln_type['count']} |\n"
            content += "\n"

        # 添加详细分析结果
        if file_results:
            content += "## 📋 详细分析结果\n\n"
            for i, file_result in enumerate(file_results, 1):
                content += self._generate_file_section(file_result, i, stats)

        # 添加安全建议
        content += self._generate_recommendations_section(file_results, stats)

        # 添加修复指南
        content += self._generate_remediation_guide()

        # 添加技术说明
        content += self._generate_technical_notes()

        return content

    def _generate_file_section(
        self, file_result: AnalysisResult, index: int, stats: Dict[str, Any]
    ) -> str:
        """生成单个文件的报告章节"""
        file_path = file_result.file_path
        vulnerabilities = file_result.vulnerabilities
        security_score = file_result.security_score
        status = file_result.analysis_status

        section = f"""### 📄 文件 {index}: `{file_path}`\n\n"""

        if status == "error":
            error_msg = (
                file_result.recommendations[0]
                if file_result.recommendations
                else "未知错误."
            )
            section += f"\n❌ **分析失败**: {error_msg}\n\n"
            return section

        # 安全评分
        score_color = (
            "🟢" if security_score >= 80 else "🟡" if security_score >= 60 else "🔴"
        )
        section += f"**🔒 安全评分**: {score_color} {security_score}/100\n\n"

        if not vulnerabilities:
            section += "✅ **未检测到安全漏洞**.\n\n"
            return section

        # 按严重度分组
        vuln_by_severity = self._group_vulnerabilities_by_severity(vulnerabilities)

        for severity, vuln_list in vuln_by_severity.items():
            if vuln_list:
                emoji = self.severity_colors.get(severity, "⚪")
                name = self.severity_names.get(severity, severity)
                section += f"#### {emoji} {name}漏洞 ({len(vuln_list)}个)\n\n"

                for j, vuln in enumerate(vuln_list, 1):
                    section += self._generate_vulnerability_detail(vuln, j)

        return section

    def _generate_vulnerability_detail(self, vuln: Vulnerability, index: int) -> str:
        """生成单个漏洞的详细信息"""
        emoji = self.severity_colors.get(vuln.severity.value, "⚪")

        detail = f"""**{index}. {emoji} {vuln.type}**\n\n"""
        detail += f"- **位置**: 第{vuln.line}行\n"
        detail += f"- **严重度**: {self._format_severity(vuln.severity)}\n"
        detail += f"- **置信度**: {vuln.confidence:.1%}\n"
        detail += f"- **描述**: {vuln.description}\n"

        if vuln.code_snippet:
            detail += f"- **相关代码**: \n```python\n{vuln.code_snippet}\n```\n"

        detail += f"- **修复建议**: {vuln.remediation}\n"

        if vuln.cwe_id:
            detail += f"- **CWE编号**: {vuln.cwe_id}\n"

        if vuln.owasp_category:
            detail += f"- **OWASP分类**: {vuln.owasp_category}\n"

        detail += "\n---\n\n"
        return detail

    def _generate_recommendations_section(
        self, file_results: List[AnalysisResult], stats: Dict[str, Any]
    ) -> str:
        """生成安全建议章节"""
        all_recommendations = set()

        for file_result in file_results:
            all_recommendations.update(file_result.recommendations)

        if not all_recommendations:
            return "\n## 💡 安全建议\n\n✅ 代码整体安全性良好，暂无特别建议。\n\n"

        section = "\n## 💡 安全建议\n\n"
        section += f"基于本次扫描结果，我们提供以下 {len(all_recommendations)} 条安全建议：\n\n"

        for i, rec in enumerate(sorted(all_recommendations), 1):
            section += f"{i}. {rec}\n"

        section += "\n"
        return section

    def _generate_remediation_guide(self) -> str:
        """生成修复指南"""
        return """
## 🔧 漏洞修复指南

### SQL注入防护
- 使用参数化查询（Prepared Statements）
- 验证和清理所有用户输入
- 使用ORM框架的安全方法

### 命令注入防护
- 避免使用 `os.system()`，改用 `subprocess` 模块的安全方法
- 对用户输入进行严格验证
- 使用白名单方式限制输入

### 加密安全
- 使用强加密算法（如SHA-256、AES-256）
- 密钥不要硬编码在代码中，使用环境变量或密钥管理服务
- 使用安全的随机数生成器（如 `secrets` 模块）

### 敏感信息保护
- 从代码中移除所有硬编码的敏感信息
- 使用配置文件或环境变量存储敏感数据
- 在生产环境中关闭调试模式

### 输入验证
- 对所有用户输入进行验证和清理
- 使用白名单而非黑名单方法
- 实施适当的错误处理机制

### 安全编码最佳实践
1. **最小权限原则**: 只授予必要的权限
2. **防御深度**: 实施多层次的安全防护
3. **失败安全**: 系统出错时默认拒绝访问
4. **安全默认值**: 默认配置应该是安全的
5. **完整审计**: 记录所有安全相关事件

"""

    def _generate_technical_notes(self) -> str:
        """生成技术说明"""
        return f"""
## 📋 技术说明

### 扫描工具信息
- **工具名称**: AI代码安全审计CLI工具
- **版本**: 2.0.0
- **分析引擎**: 混合分析（AI + 本地规则）
- **扫描时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

### 漏洞严重度分级
- **🔴 严重**: 可能导致系统完全被控制，需要立即修复
- **🔴 高危**: 可能导致严重的安全问题，需要尽快修复
- **🟡 中危**: 可能导致安全问题，建议在方便时修复
- **🟢 低危**: 潜在的安全风险，可以在维护时修复

### 检测能力
- **SQL注入**: 检测不安全的SQL查询构造
- **命令注入**: 发现危险的系统命令执行
- **加密问题**: 识别弱加密算法和不安全实现
- **敏感信息**: 发现硬编码的密钥和密码
- **XSS漏洞**: 检测跨站脚本攻击向量
- **反序列化**: 发现不安全的反序列化操作
- **路径遍历**: 检测目录遍历漏洞
- **信息泄露**: 发现可能泄露敏感信息的代码

### 免责声明
本报告由AI自动生成，仅供参考。建议结合人工审查来确保代码安全性。
对于关键业务系统，建议进行专业的安全审计。

---
*报告由 AI代码安全审计工具 v2.0.0 生成*
"""


class JsonReportGenerator(BaseReportGenerator):
    """JSON报告生成器"""

    def generate_report(
        self, results: Dict[str, Any], output_path: Optional[str] = None
    ) -> None:
        """生成JSON报告"""
        try:
            json_data = self._build_json_content(results)

            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
            else:
                print(json.dumps(json_data, indent=2, ensure_ascii=False))

        except Exception as e:
            raise RuntimeError(f"生成JSON报告失败: {e}.")

    def _build_json_content(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """构建JSON内容"""
        stats = self._calculate_statistics(results)
        file_results = results.get("file_results", [])

        return {
            "scan_metadata": {
                "tool_name": "AI Code Security Audit Tool",
                "version": "2.0.0",
                "scan_timestamp": datetime.now().isoformat(),
                "analysis_engine": results.get("scan_summary", {}).get(
                    "analysis_engine", "hybrid"
                ),
                "scan_duration": stats["scan_time"],
            },
            "summary": {
                "total_files": stats["total_files"],
                "total_vulnerabilities": stats["total_vulnerabilities"],
                "files_with_issues": stats["files_with_issues"],
                "risk_assessment": stats["risk_assessment"],
                "severity_breakdown": stats["severity_breakdown"],
                "top_vulnerability_types": stats["top_vulnerability_types"],
            },
            "results": [
                self._standardize_file_result(result) for result in file_results
            ],
            "recommendations": self._extract_all_recommendations(results),
            "statistics": {
                "average_vulnerabilities_per_file": round(
                    stats["total_vulnerabilities"] / max(stats["total_files"], 1), 2
                ),
                "most_common_severity": self._get_most_common_severity(
                    stats["severity_breakdown"]
                ),
                "scan_efficiency": self._calculate_scan_efficiency(stats),
            },
        }

    def _standardize_file_result(self, file_result: AnalysisResult) -> Dict[str, Any]:
        """标准化单个文件结果"""
        return {
            "file_path": file_result.file_path,
            "file_size": file_result.file_size,
            "analysis_status": file_result.analysis_status,
            "security_score": file_result.security_score,
            "vulnerabilities": [
                {
                    "id": f"{vuln.type}_{vuln.line}",
                    "type": vuln.type,
                    "severity": vuln.severity.value,
                    "severity_level": vuln.severity.name,
                    "line": vuln.line,
                    "description": vuln.description,
                    "remediation": vuln.remediation,
                    "code_snippet": vuln.code_snippet,
                    "confidence": vuln.confidence,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "metadata": {
                        "detected_by": "hybrid_analysis",
                        "detection_timestamp": datetime.now().isoformat(),
                    },
                }
                for vuln in file_result.vulnerabilities
            ],
            "recommendations": file_result.recommendations,
        }

    def _extract_all_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """提取所有推荐建议"""
        recommendations = set()
        for file_result in results.get("file_results", []):
            recommendations.update(file_result.get("recommendations", []))
        return list(recommendations)

    def _get_most_common_severity(self, severity_breakdown: Dict[str, Any]) -> str:
        """获取最常见的严重度"""
        if not severity_breakdown:
            return "none"

        max_count = 0
        most_common = "none"
        for severity, info in severity_breakdown.items():
            if info["count"] > max_count:
                max_count = info["count"]
                most_common = severity
        return most_common

    def _calculate_scan_efficiency(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """计算扫描效率"""
        return {
            "vulnerabilities_per_second": round(
                stats["total_vulnerabilities"] / max(stats["scan_time"], 0.1), 2
            ),
            "files_per_second": round(
                stats["total_files"] / max(stats["scan_time"], 0.1), 2
            ),
            "efficiency_score": min(
                100,
                int(stats["total_vulnerabilities"] / max(stats["total_files"], 1) * 10),
            ),
        }


class HtmlReportGenerator(BaseReportGenerator):
    """HTML报告生成器"""

    def generate_report(
        self, results: Dict[str, Any], output_path: Optional[str] = None
    ) -> None:
        """生成HTML报告"""
        try:
            html_content = self._build_html_content(results)

            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
            else:
                print(html_content)

        except Exception as e:
            raise RuntimeError(f"生成HTML报告失败: {e}.")

    def _build_html_content(self, results: Dict[str, Any]) -> str:
        """构建HTML内容"""
        stats = self._calculate_statistics(results)
        file_results = results.get("file_results", [])
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI代码安全审计报告</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        .summary-card.high-risk {{
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }}
        .summary-card.medium-risk {{
            border-left-color: #f39c12;
            background: #fef9f3;
        }}
        .summary-card.low-risk {{
            border-left-color: #27ae60;
            background: #f0f9f0;
        }}
        .vulnerability {{
            background: #fff;
            border: 1px solid #e1e8ed;
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        .vulnerability.critical {{
            border-left: 4px solid #e74c3c;
        }}
        .vulnerability.high {{
            border-left: 4px solid #e67e22;
        }}
        .vulnerability.medium {{
            border-left: 4px solid #f39c12;
        }}
        .vulnerability.low {{
            border-left: 4px solid #27ae60;
        }}
        .code-snippet {{
            background: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .recommendation {{
            background: #e8f4fd;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .stats-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .stats-table th, .stats-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .stats-table th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity-critical {{ background: #e74c3c; color: white; }}
        .severity-high {{ background: #e67e22; color: white; }}
        .severity-medium {{ background: #f39c12; color: white; }}
        .severity-low {{ background: #27ae60; color: white; }}
        .progress-bar {{
            background: #ecf0f1;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #f39c12, #e74c3c);
            transition: width 0.3s ease;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 AI代码安全审计报告</h1>
        <p><strong>生成时间:</strong> {current_time}</p>
        <p><strong>分析引擎:</strong> {results.get('scan_summary', {}).get('analysis_engine', '混合分析')}</p>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>📊 扫描统计</h3>
                <p><strong>文件数:</strong> {stats['total_files']}</p>
                <p><strong>漏洞数:</strong> {stats['total_vulnerabilities']}</p>
                <p><strong>扫描时间:</strong> {stats['scan_time']}秒</p>
            </div>
            <div class="summary-card {self._get_risk_css_class(stats['risk_assessment'])}">
                <h3>⚠️ 风险等级</h3>
                <p><strong>{stats['risk_assessment']}</strong></p>
                <p>问题文件: {stats['files_with_issues']}</p>
            </div>
        </div>

        <h2>📈 漏洞分布</h2>
        <div class="stats-table">
            <table>
                <thead>
                    <tr>
                        <th>严重度</th>
                        <th>数量</th>
                        <th>百分比</th>
                        <th>分布图</th>
                    </tr>
                </thead>
                <tbody>
"""

        # 添加漏洞分布表
        for severity, info in stats["severity_breakdown"].items():
            if info["count"] > 0:
                emoji = self.severity_colors.get(severity, "⚪")
                name = self.severity_names.get(severity, severity)
                percentage = info["percentage"]
                bar_width = int(percentage * 2)

                html += f"""
                    <tr>
                        <td>{emoji} {name}</td>
                        <td>{info['count']}</td>
                        <td>{percentage:.1f}%</td>
                        <td>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {bar_width}px;"></div>
                            </div>
                        </td>
                    </tr>
"""

        html += """
                </tbody>
            </table>
        </div>

        <h2>📋 详细分析结果</h2>
"""

        # 添加详细的漏洞信息
        for i, file_result in enumerate(file_results, 1):
            html += self._generate_html_file_section(file_result, i)

        # 添加安全建议
        html += self._generate_html_recommendations_section(file_results)

        html += """
    </div>
</body>
</html>
"""

        return html

    def _get_risk_css_class(self, risk_level: str) -> str:
        """获取风险等级对应的CSS类"""
        risk_class_map = {
            "极高风险": "high-risk",
            "高风险": "medium-risk",
            "中等风险": "low-risk",
            "低风险": "low-risk",
        }
        return risk_class_map.get(risk_level, "low-risk")

    def _generate_html_file_section(
        self, file_result: AnalysisResult, index: int
    ) -> str:
        """生成HTML文件部分"""
        file_path = file_result.file_path
        vulnerabilities = file_result.vulnerabilities
        security_score = file_result.security_score

        section = f"""
        <div class="file-result">
            <h3>📄 文件 {index}: {file_path}</h3>
            <p><strong>安全评分:</strong> {security_score}/100</p>
"""

        if not vulnerabilities:
            section += "<p>✅ 未检测到安全漏洞</p>"
        else:
            # 按严重度分组显示
            vuln_by_severity = self._group_vulnerabilities_by_severity(vulnerabilities)

            for severity, vuln_list in vuln_by_severity.items():
                if vuln_list:
                    section += f"<h4>{self._format_severity(vuln_list[0].severity)} 漏洞 ({len(vuln_list)}个)</h4>"
                    for vuln in vuln_list:
                        section += self._generate_html_vulnerability(vuln)

        section += "</div>"
        return section

    def _generate_html_vulnerability(self, vuln: Vulnerability) -> str:
        """生成HTML漏洞信息"""
        return f"""
        <div class="vulnerability {vuln.severity.value}">
            <h4>{vuln.type} (第{vuln.line}行)</h4>
            <p><strong>严重度:</strong> <span class="severity-badge severity-{vuln.severity.value}">
                {self._format_severity(vuln.severity)}
            </span></p>
            <p><strong>置信度:</strong> {vuln.confidence:.1%}</p>
            <p><strong>描述:</strong> {vuln.description}</p>
            {f'<div class="code-snippet">{vuln.code_snippet}</div>' if vuln.code_snippet else ''}
            <p><strong>修复建议:</strong> {vuln.remediation}</p>
            {f'<p><strong>CWE:</strong> {vuln.cwe_id}</p>' if vuln.cwe_id else ''}
            {f'<p><strong>OWASP:</strong> {vuln.owasp_category}</p>' if vuln.owasp_category else ''}
        </div>
"""

    def _generate_html_recommendations_section(
        self, file_results: List[AnalysisResult]
    ) -> str:
        """生成HTML安全建议部分"""
        all_recommendations = set()
        for file_result in file_results:
            all_recommendations.update(file_result.recommendations)

        if not all_recommendations:
            return ""

        html = """
        <h2>💡 安全建议</h2>
"""
        for rec in sorted(all_recommendations):
            html += f"""
        <div class="recommendation">
            {rec}
        </div>
"""
        return html


class XmlReportGenerator(BaseReportGenerator):
    """XML报告生成器"""

    def generate_report(
        self, results: Dict[str, Any], output_path: Optional[str] = None
    ) -> None:
        """生成XML报告"""
        try:
            xml_content = self._build_xml_content(results)

            # 格式化XML
            dom = minidom.parseString(xml_content)
            pretty_xml = dom.toprettyxml(indent="  ")

            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(pretty_xml)
            else:
                print(pretty_xml)

        except Exception as e:
            raise RuntimeError(f"生成XML报告失败: {e}.")

    def _build_xml_content(self, results: Dict[str, Any]) -> str:
        """构建XML内容"""
        stats = self._calculate_statistics(results)
        file_results = results.get("file_results", [])

        # 创建根元素
        root = ET.Element("SecurityAuditReport")
        root.set("version", "2.0")
        root.set("generated", datetime.now().isoformat())

        # 添加元数据
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "ToolName").text = "AI Code Security Audit Tool"
        ET.SubElement(metadata, "Version").text = "2.0.0"
        ET.SubElement(metadata, "AnalysisEngine").text = results.get(
            "scan_summary", {}
        ).get("analysis_engine", "hybrid")
        ET.SubElement(metadata, "ScanDuration").text = str(stats["scan_time"])

        # 添加摘要
        summary = ET.SubElement(root, "Summary")
        ET.SubElement(summary, "TotalFiles").text = str(stats["total_files"])
        ET.SubElement(summary, "TotalVulnerabilities").text = str(
            stats["total_vulnerabilities"]
        )
        ET.SubElement(summary, "FilesWithIssues").text = str(stats["files_with_issues"])
        ET.SubElement(summary, "RiskAssessment").text = stats["risk_assessment"]

        # 添加严重度分布
        severity_dist = ET.SubElement(summary, "SeverityDistribution")
        for severity, info in stats["severity_breakdown"].items():
            if info["count"] > 0:
                severity_elem = ET.SubElement(severity_dist, "Severity")
                severity_elem.set("level", severity)
                severity_elem.set("count", str(info["count"]))
                severity_elem.set("percentage", f"{info['percentage']:.1f}")

        # 添加结果
        results_elem = ET.SubElement(root, "Results")
        for file_result in file_results:
            self._add_file_result_to_xml(results_elem, file_result)

        # 添加推荐建议
        recommendations = ET.SubElement(root, "Recommendations")
        all_recommendations = self._extract_all_recommendations(results)
        for rec in all_recommendations:
            ET.SubElement(recommendations, "Recommendation").text = rec

        # 转换为字符串
        return ET.tostring(root, encoding="unicode")

    def _add_file_result_to_xml(
        self, parent: ET.Element, file_result: AnalysisResult
    ) -> None:
        """添加文件结果到XML"""
        file_elem = ET.SubElement(parent, "File")
        file_elem.set("path", file_result.file_path)
        file_elem.set("size", str(file_result.file_size))
        file_elem.set("status", file_result.analysis_status)
        file_elem.set("securityScore", str(file_result.security_score))

        vulnerabilities = ET.SubElement(file_elem, "Vulnerabilities")
        for vuln in file_result.vulnerabilities:
            vuln_elem = ET.SubElement(vulnerabilities, "Vulnerability")
            vuln_elem.set("type", vuln.type)
            vuln_elem.set("severity", vuln.severity.value)
            vuln_elem.set("line", str(vuln.line))
            vuln_elem.set("confidence", str(vuln.confidence))

            ET.SubElement(vuln_elem, "Description").text = vuln.description
            ET.SubElement(vuln_elem, "Remediation").text = vuln.remediation
            ET.SubElement(vuln_elem, "CodeSnippet").text = vuln.code_snippet

            if vuln.cwe_id:
                ET.SubElement(vuln_elem, "CWE").text = vuln.cwe_id
            if vuln.owasp_category:
                ET.SubElement(vuln_elem, "OWASPCategory").text = vuln.owasp_category

        # 添加推荐建议
        file_recommendations = ET.SubElement(file_elem, "Recommendations")
        for rec in file_result.recommendations:
            ET.SubElement(file_recommendations, "Recommendation").text = rec

    def _extract_all_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """提取所有推荐建议"""
        recommendations = set()
        for file_result in results.get("file_results", []):
            recommendations.update(file_result.recommendations)
        return list(recommendations)


# 报告生成器工厂
class ReportGeneratorFactory:
    """报告生成器工厂"""

    @staticmethod
    def create_report_generator(
        generator_type: str = "console", **kwargs
    ) -> IReportGenerator:
        """创建报告生成器实例"""
        generator_type = generator_type.lower()

        if generator_type == "console":
            return ConsoleReportGenerator(**kwargs)
        elif generator_type == "markdown":
            return MarkdownReportGenerator(**kwargs)
        elif generator_type == "json":
            return JsonReportGenerator(**kwargs)
        elif generator_type == "html":
            return HtmlReportGenerator(**kwargs)
        elif generator_type == "xml":
            return XmlReportGenerator(**kwargs)
        else:
            raise ValueError(f"不支持的报告生成器类型: {generator_type}.")

    @staticmethod
    def get_supported_formats() -> List[str]:
        """获取支持的报告格式"""
        return ["console", "markdown", "json", "html", "xml"]

    @staticmethod
    def get_format_info(format_type: str) -> Dict[str, Any]:
        """获取格式信息"""
        format_info = {
            "console": {
                "description": "控制台输出，适合命令行查看",
                "file_extension": None,
                "use_case": "快速查看分析结果",
            },
            "markdown": {
                "description": "Markdown格式，适合文档和分享",
                "file_extension": ".md",
                "use_case": "生成可读的审计报告",
            },
            "json": {
                "description": "JSON格式，适合程序化处理",
                "file_extension": ".json",
                "use_case": "集成到其他工具或系统",
            },
            "html": {
                "description": "HTML格式，适合网页查看",
                "file_extension": ".html",
                "use_case": "生成交互式报告",
            },
            "xml": {
                "description": "XML格式，适合企业集成",
                "file_extension": ".xml",
                "use_case": "与传统安全工具集成",
            },
        }
        return format_info.get(format_type, {})
