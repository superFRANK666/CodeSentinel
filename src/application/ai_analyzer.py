#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版AI代码分析器
支持多种AI模型，包括本地模型和云API
"""

import os
import asyncio
import json
import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

import openai
from openai import AsyncOpenAI

from ..core.interfaces import ICodeAnalyzer, AnalysisResult, Vulnerability, SeverityLevel, AnalyzerConfig
from ..core.analyzers.base_analyzer import BaseCodeAnalyzer


logger = logging.getLogger(__name__)


class AICodeAnalyzer(BaseCodeAnalyzer):
    """增强版AI代码分析器"""

    def __init__(self, model: str = "gpt-4o-mini", timeout: int = 60, max_retries: int = 3, base_url: Optional[str] = None):
        super().__init__()
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_url = base_url
        self.client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """初始化AI客户端"""
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            logger.warning("OpenAI API密钥未设置, AI分析器将处于不可用状态")
            return

        try:
            self.client = AsyncOpenAI(
                api_key=api_key,
                base_url=self.base_url,
                timeout=self.timeout,
                max_retries=self.max_retries
            )
        except Exception as e:
            logger.error(f"初始化OpenAI客户端失败: {e}.")
            self.client = None

    async def analyze_file(self, file_path: Path,
                           severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """分析单个文件"""
        if not self.client:
            return self._create_error_result(file_path, "AI分析器未初始化，请检查API密钥配置")

        try:
            # 预分析
            content = self._read_file_safely(file_path)
            if not content:
                return self._create_error_result(file_path, "无法读取文件内容")

            pre_analysis = self._pre_analyze_content(content)

            # AI深度分析
            ai_analysis = await self._ai_security_analysis(content, pre_analysis)

            # 转换结果格式
            result = self._convert_ai_result(file_path, content, ai_analysis, severity_filter)

            return result

        except Exception as e:
            logger.error(f"AI分析文件失败 {file_path}: {e}.")
            return self._create_error_result(file_path, f"AI分析失败: {str(e)}.")

    async def _ai_security_analysis(self, content: str,
                                    pre_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """使用AI进行深度安全分析"""
        if not self.client:
            return self._create_ai_error_result("AI客户端未初始化")

        # 构建增强的分析提示词
        prompt = self._build_enhanced_analysis_prompt(content, pre_analysis)

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """你是一位顶级的代码安全审计专家，专门负责Python代码安全分析。
你的任务是深度分析代码中的安全漏洞，并按照严格的JSON格式返回结果。

分析要求：
1. 识别所有类型的安全漏洞（Web安全、加密问题、逆向工程风险）
2. 为每个漏洞提供准确的严重度评级（critical/high/medium/low）
3. 提供具体的修复建议和最佳实践
4. 给出整体安全评分（0-100分）
5. 标注相关的CWE编号和OWASP分类（如果适用）
6. 提供检测置信度（0.0-1.0）

返回格式必须严格遵循JSON结构：
{
    "vulnerabilities": [
        {
            "type": "漏洞类型",
            "severity": "critical|high|medium|low",
            "line": 行号,
            "description": "详细描述",
            "remediation": "修复建议",
            "code_snippet": "相关代码片段",
            "confidence": 0.95,
            "cwe_id": "CWE-79",
            "owasp_category": "A03:2021 – Injection"
        }
    ],
    "security_score": 75,
    "recommendations": ["建议1", "建议2"],
    "summary": "整体安全评估摘要"
}"""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=4000,
                response_format={"type": "json_object"}  # 强制JSON格式输出
            )

            # 解析AI响应 - 增强错误处理
            ai_response = response.choices[0].message.content

            # 先验证响应内容不为空
            if not ai_response or not ai_response.strip():
                logger.error("AI响应内容为空")
                return self._create_ai_error_result("AI响应内容为空")

            # 尝试清理响应内容，移除可能的非JSON字符
            cleaned_response = ai_response.strip()

            try:
                parsed_result = json.loads(cleaned_response)

                # 验证解析结果的基本结构
                if not isinstance(parsed_result, dict):
                    logger.error(f"AI响应不是有效的JSON对象，类型: {type(parsed_result)}")
                    return self._create_ai_error_result("AI响应格式不正确，期望JSON对象")

                # 验证必需字段
                required_fields = ["vulnerabilities", "security_score", "recommendations"]
                missing_fields = [field for field in required_fields if field not in parsed_result]

                if missing_fields:
                    logger.error(f"AI响应缺少必需字段: {missing_fields}")
                    # 尝试构建一个包含可用字段的有效响应
                    safe_result = {
                        "vulnerabilities": parsed_result.get("vulnerabilities", []),
                        "security_score": parsed_result.get("security_score", -1),
                        "recommendations": parsed_result.get("recommendations", ["AI响应格式不完整"]),
                        "summary": parsed_result.get("summary", "AI分析结果")
                    }
                    return safe_result

                return parsed_result

            except json.JSONDecodeError as e:
                logger.error(f"AI响应JSON解析失败: {e}, 原始响应: {cleaned_response[:200]}...")

                # 尝试从响应中提取可能的JSON片段
                json_match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
                if json_match:
                    try:
                        partial_result = json.loads(json_match.group())
                        logger.warning("从AI响应中提取到部分JSON数据")
                        return partial_result
                    except json.JSONDecodeError:
                        pass

                return self._create_ai_error_result(f"AI响应格式错误: {str(e)}")

        except openai.RateLimitError:
            return self._create_ai_error_result("OpenAI API请求频率超限, 请稍后再试")
        except openai.APIConnectionError:
            return self._create_ai_error_result("无法连接到OpenAI API服务")
        except openai.AuthenticationError:
            return self._create_ai_error_result("OpenAI API认证失败, 请检查API密钥")
        except Exception as e:
            logger.error(f"AI分析出错: {e}.")
            return self._create_ai_error_result(f"AI分析出错: {str(e)}.")

    def _build_enhanced_analysis_prompt(self, content: str,
                                        pre_analysis: Dict[str, Any]) -> str:
        """构建增强的分析提示词"""
        vulnerability_types = """
请重点检查以下安全漏洞类型：

【高危漏洞】
1. SQL注入：字符串拼接、参数化查询不当、ORM误用
2. 命令注入：os.system、subprocess、shell=True
3. 代码注入：eval、exec、pickle.loads、yaml.load
4. 反序列化漏洞：pickle、不安全的序列化
5. 路径遍历：../、绝对路径、文件包含
6. 硬编码敏感信息：API密钥、密码、私钥、证书

【中危漏洞】
1. 弱加密算法：MD5、SHA1、DES、RC4
2. 不安全的随机数：random模块用于安全场景
3. XSS漏洞：模板渲染、HTML输出未转义
4. SSRF漏洞：未验证的URL请求、内网访问
5. 不安全的直接对象引用：IDOR、权限绕过
6. 会话管理问题：可预测会话ID、过期时间

【低危漏洞】
1. 信息泄露：详细错误信息、调试信息
2. 不安全的HTTP头：CSP缺失、XSS保护
3. 代码质量问题：硬编码数值、魔法数字
4. 资源管理：文件句柄未关闭、内存泄漏
"""

        prompt = f"""
请对以下Python代码进行深度安全分析：

文件统计信息：
- 总行数: {pre_analysis['total_lines']}
- 代码行数: {pre_analysis['code_lines']}
- 导入模块数: {len(pre_analysis['import_statements'])}
- 函数定义数: {len(pre_analysis['function_definitions'])}
- 类定义数: {len(pre_analysis['class_definitions'])}

代码内容：
```python
{content}
```

{vulnerability_types}

分析要求：
1. 逐行仔细分析代码，识别所有潜在的安全问题
2. 对每个发现的问题提供详细的解释和影响分析
3. 给出具体的修复代码示例
4. 评估问题的严重程度和利用难度
5. 提供预防类似问题的开发建议

请严格按照JSON格式返回分析结果，确保数据结构完整且符合要求。
"""
        return prompt

    def _convert_ai_result(self, file_path: Path, content: str,
                           ai_result: Dict[str, Any],
                           severity_filter: SeverityLevel) -> AnalysisResult:
        """转换AI分析结果为标准格式"""
        vulnerabilities = []

        # 转换漏洞信息
        for vuln_data in ai_result.get("vulnerabilities", []):
            severity = self._parse_severity(vuln_data.get("severity", "low"))

            # 过滤严重度
            if not self._should_include_vulnerability(severity, severity_filter):
                continue

            vulnerability = Vulnerability(
                type=vuln_data.get("type", "Unknown"),
                severity=severity,
                line=vuln_data.get("line", 0),
                description=vuln_data.get("description", "无描述"),
                remediation=vuln_data.get("remediation", "无修复建议"),
                code_snippet=vuln_data.get("code_snippet", "")[:200],
                confidence=vuln_data.get("confidence", 0.8),
                cwe_id=vuln_data.get("cwe_id"),
                owasp_category=vuln_data.get("owasp_category")
            )
            vulnerabilities.append(vulnerability)

        # 计算安全评分
        security_score = ai_result.get("security_score", 100)
        if security_score == -1:  # AI分析失败的标志
            security_score = 0

        # 生成推荐建议
        recommendations = ai_result.get("recommendations", [])
        if not recommendations:
            recommendations = self._generate_default_recommendations(vulnerabilities)

        return AnalysisResult(
            file_path=str(file_path),
            file_size=len(content),
            analysis_status="completed",
            vulnerabilities=vulnerabilities,
            security_score=security_score,
            recommendations=recommendations,
            analysis_time=0.0,  # 将在外层计算
            pre_analysis_info=None
        )

    def _parse_severity(self, severity_str: str) -> SeverityLevel:
        """解析严重度字符串"""
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW
        }
        return severity_map.get(severity_str.lower(), SeverityLevel.LOW)

    def _should_include_vulnerability(self, severity: SeverityLevel,
                                      filter_level: SeverityLevel) -> bool:
        """判断是否应该包含该漏洞"""
        severity_order = {
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        return severity_order.get(severity, 1) >= severity_order.get(filter_level, 1)

    def _generate_default_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """生成默认的安全建议"""
        recommendations = set()

        for vuln in vulnerabilities:
            vuln_type = vuln.type.lower()

            if "sql" in vuln_type:
                recommendations.add("使用参数化查询防止SQL注入")
                recommendations.add("实施输入验证和清理")
            elif "command" in vuln_type:
                recommendations.add("避免直接执行用户输入")
                recommendations.add("使用安全的API替代系统命令")
            elif "crypto" in vuln_type or "encryption" in vuln_type:
                recommendations.add("使用现代强加密算法")
                recommendations.add("定期更新加密库")
            elif "hardcoded" in vuln_type or "secret" in vuln_type:
                recommendations.add("将敏感信息移至环境变量")
                recommendations.add("使用密钥管理服务")
            elif "xss" in vuln_type:
                recommendations.add("对用户输入进行HTML转义")
                recommendations.add("使用安全的模板引擎")
            elif "deserialize" in vuln_type:
                recommendations.add("避免反序列化不可信数据")
                recommendations.add("使用安全的序列化格式")

        # 通用建议
        recommendations.add("定期更新依赖库")
        recommendations.add("实施代码审查流程")
        recommendations.add("使用自动化安全测试工具")

        return list(recommendations)

    def _create_ai_error_result(self, error_message: str) -> Dict[str, Any]:
        """创建AI分析错误结果"""
        return {
            "vulnerabilities": [],
            "security_score": -1,  # 特殊标记表示分析失败
            "recommendations": [f"AI分析出错: {error_message}"],
            "summary": "AI分析失败"
        }

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        return {
            "name": "AICodeAnalyzer",
            "version": "2.0.0",
            "description": "基于OpenAI GPT模型的智能代码安全分析器",
            "model": self.model,
            "features": [
                "AI驱动的深度安全分析",
                "支持多种漏洞类型检测",
                "智能修复建议生成",
                "置信度评估",
                "CWE/OWASP分类支持"
            ],
            "requirements": [
                "OpenAI API密钥",
                "网络连接"
            ],
            "status": "active" if self.client else "inactive"
        }


class OfflineAIModel:
    """离线AI模型包装器（预留接口）"""

    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self) -> None:
        """加载离线模型"""
        # 这里可以集成各种离线AI模型
        # 例如：CodeBERT、GraphCodeBERT、CodeT5等
        logger.info(f"正在加载离线AI模型: {self.model_path}")
        # 实际实现将取决于具体的模型类型和框架
        pass

    async def analyze_code(self, content: str) -> Dict[str, Any]:
        """分析代码"""
        if not self.model:
            return {"error": "离线模型未加载"}

        # 这里实现具体的模型推理逻辑
        # 返回与OpenAI API兼容的结果格式
        return {
            "vulnerabilities": [],
            "security_score": 100,
            "recommendations": ["离线模型分析结果"]
        }


class LocalLLMAnalyzer(BaseCodeAnalyzer):
    """本地LLM分析器（支持Ollama、LMStudio等）"""

    def __init__(self, model_name: str = "codellama", base_url: str = "http://localhost:11434"):
        super().__init__()
        self.model_name = model_name
        self.base_url = base_url
        self.client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """初始化本地LLM客户端"""
        try:
            # 支持Ollama API
            import httpx
            self.client = httpx.AsyncClient(base_url=self.base_url, timeout=30.0)
        except ImportError:
            logger.error("httpx库未安装，无法使用本地LLM分析器")
            self.client = None

    async def analyze_file(self, file_path: Path,
                           severity_filter: SeverityLevel = SeverityLevel.LOW) -> AnalysisResult:
        """使用本地LLM分析文件"""
        if not self.client:
            return self._create_error_result(file_path, "本地LLM客户端未初始化")

        try:
            content = self._read_file_safely(file_path)
            if not content:
                return self._create_error_result(file_path, "无法读取文件内容")

            # 构建分析请求
            prompt = self._build_local_llm_prompt(content, file_path)

            # 调用本地LLM API
            response = await self.client.post(
                "/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9
                    }
                }
            )

            if response.status_code != 200:
                return self._create_error_result(file_path, f"本地LLM调用失败: {response.status_code}")

            result = response.json()
            return self._parse_local_llm_result(file_path, content, result, severity_filter)

        except Exception as e:
            logger.error(f"本地LLM分析失败 {file_path}: {e}.")
            return self._create_error_result(file_path, f"本地LLM分析失败: {str(e)}.")

    def _build_local_llm_prompt(self, content: str, file_path: Path) -> str:
        """构建本地LLM分析提示词"""
        return f"""请分析以下Python代码的安全漏洞：

文件: {file_path.name}

代码内容：
```python
{content}
```

请识别安全漏洞并提供JSON格式的分析结果，包括：
1. 漏洞列表（类型、严重度、行号、描述、修复建议）
2. 整体安全评分（0-100）
3. 安全建议

返回格式：
{{
    "vulnerabilities": [{{"type": "", "severity": "", "line": 0, "description": "", "remediation": ""}}],
    "security_score": 85,
    "recommendations": [""]
}}"""

    def _parse_local_llm_result(self, file_path: Path, content: str,
                                llm_result: Dict[str, Any],
                                severity_filter: SeverityLevel) -> AnalysisResult:
        """解析本地LLM结果"""
        # 解析响应文本中的JSON
        try:
            response_text = llm_result.get("response", "")
            # 尝试从响应中提取JSON
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                analysis_result = json.loads(json_match.group())
            else:
                analysis_result = {"vulnerabilities": [], "security_score": 100, "recommendations": []}
        except Exception:
            analysis_result = {"vulnerabilities": [], "security_score": 100, "recommendations": []}

        return self._convert_ai_result(file_path, content, analysis_result, severity_filter)

    def get_analyzer_info(self) -> Dict[str, Any]:
        """获取分析器信息"""
        return {
            "name": "LocalLLMAnalyzer",
            "version": "1.0.0",
            "description": "基于本地LLM的代码安全分析器",
            "model": self.model_name,
            "base_url": self.base_url,
            "features": [
                "本地AI模型支持",
                "无需外部API",
                "代码隐私保护"
            ],
            "requirements": [
                "本地LLM服务（如Ollama）"
            ],
            "status": "active" if self.client else "inactive"
        }
