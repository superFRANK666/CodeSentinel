<p align="right"><a href="README.md">English</a></p>

# CodeSentinel: AI 驱动的多语言代码安全审计器

<div align="center">

![CodeSentinel Logo](https://img.shields.io/badge/CodeSentinel-v2.0-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.10+-green?style=for-the-badge&logo=python)](https://python.org)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?style=for-the-badge&logo=javascript)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)

**先进的 AI 驱动的 Python 和 JavaScript 安全审计工具**

CodeSentinel 结合本地静态分析、AI 驱动的深度检查和行业标准工具，为现代代码库提供全面的漏洞检测。

</div>

## ✨ 主要功能

### 🌍 多语言支持
- **Python**: 完整的 AST 分析、污点分析和 AI 驱动的检查
- **JavaScript**: ESLint 集成，专注安全规则
- **自动检测**: 自动识别文件类型并选择合适的分析器

### 🔍 高级分析能力
- **混合分析引擎**: 结合 AST/污点分析速度与 AI 深度检查
- **多种分析器模式**: `local`、`ai`、`hybrid` 和 `multi_language` 模式
- **实时漏洞检测**: 全面的安全模式匹配

### 🛡️ 全面的漏洞覆盖
- **注入攻击**: SQL、命令、代码注入
- **Web 安全**: XSS、CSRF、路径遍历
- **加密问题**: 弱算法、不安全的随机性
- **数据泄露**: 硬编码秘密、敏感数据泄露
- **JavaScript 特定**: eval() 使用、原型污染、不安全的动态代码

### 🚀 性能与可用性
- **智能缓存**: 显著加速后续扫描
- **并行处理**: 并发分析多个文件
- **丰富的报告**: 控制台、Markdown、JSON、HTML、XML 格式
- **进度跟踪**: 实时分析进度指示

### 🔧 可扩展性
- **插件架构**: 轻松添加新的分析器和报告器
- **可配置规则**: 自定义安全规则集
- **CI/CD 集成**: 完美适用于自动化安全流水线

## 📋 系统要求

### 核心依赖
- **Python 3.10+**: 核心分析引擎
- **Node.js 16+ 和 npm**: JavaScript 分析所需的 ESLint

### 可选依赖
- **OpenAI API 密钥**: AI 驱动的深度分析（`ai` 和 `hybrid` 模式）

### 系统需求
- **内存**: 最低 4GB，推荐 8GB+ 用于大型代码库
- **存储**: 安装需要 500MB + 分析缓存空间
- **操作系统**: Windows 10+、macOS 10.15+ 或 Linux (Ubuntu 18.04+)

## 🚀 安装指南

### 1. 克隆仓库
```bash
git clone https://github.com/superFRANK666/CodeSentinel.git
cd CodeSentinel
```

### 2. 设置 Python 环境
```bash
# 创建虚拟环境
python -m venv venv

# 激活环境
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# 安装 Python 依赖
pip install -r requirements.txt
```

### 3. 安装 ESLint（用于 JavaScript 分析）
```bash
# 全局安装 ESLint
npm install -g eslint

# 安装安全插件
npm install -g eslint-plugin-security

# 验证安装
eslint --version
```

### 4. 配置环境
```bash
# 复制环境模板
cp docs/.env.example .env

# 编辑 .env 文件，添加您的 API 密钥
# OPENAI_API_KEY=your-openai-api-key-here
```

### 5. 验证安装
```bash
# 测试 Python 分析
python main.py --help

# 测试 JavaScript 分析（需要一个 .js 文件）
echo "console.log('test');" > test.js
python main.py test.js
rm test.js
```

## 💡 使用示例

### 基础用法
```bash
# 分析单个文件
python main.py script.py                    # Python 文件
python main.py app.js                       # JavaScript 文件

# 分析目录（自动检测文件类型）
python main.py src/                         # 混合语言
python main.py frontend/                    # JavaScript/TypeScript
python main.py backend/                     # Python
```

### 高级用法
```bash
# 使用特定分析器
python main.py src/ --analyzer local        # 快速本地分析
python main.py src/ --analyzer ai           # AI 驱动分析
python main.py src/ --analyzer hybrid       # 组合方法
python main.py src/ --analyzer multi_language  # 默认，自动检测

# 按严重程度过滤
python main.py src/ --severity high         # 仅高危漏洞
python main.py src/ --severity medium       # 中危及以上
python main.py src/ --severity critical     # 仅严重漏洞

# 生成报告
python main.py src/ --output report.md --format markdown
python main.py src/ --output report.html --format html
python main.py src/ --output results.json --format json
```

### 文件类型过滤
```bash
# 分析特定文件类型
python main.py . --include "*.py"           # 仅 Python
python main.py . --include "*.js" --include "*.jsx"  # JavaScript + React
python main.py . --include "*.py" --include "*.js"   # 两种语言

# 排除模式
python main.py src/ --exclude "test_*" --exclude "__pycache__"
python main.js src/ --exclude "*.min.js" --exclude "node_modules"
```

### 性能选项
```bash
# 显示进度和详细输出
python main.py src/ --progress --verbose

# 控制并发数
python main.py src/ --workers 8             # 8 个并行工作线程

# 缓存管理
python main.py src/ --no-cache              # 禁用缓存
python main.py --clear-cache                # 清除现有缓存
```

### 快速入门示例
```bash
# 快速安全检查
python main.py . --severity high --progress

# 使用 AI 进行全面分析
python main.py . --analyzer hybrid --output full_report.html --format html

# CI/CD 集成（对严重问题失败）
python main.py src/ --severity critical --quiet
```

## JavaScript 支持

CodeSentinel 现在通过 ESLint 集成支持 JavaScript 代码分析。JavaScript 分析器可以检测：

- **代码注入**: 使用 `eval()`、`new Function()` 等危险构造
- **XSS 漏洞**: 不安全的 `innerHTML`、`document.write()` 和 `javascript:` URL 使用
- **路径遍历**: 不安全的文件系统访问模式
- **不安全的随机性**: 使用可预测的随机数生成器
- **对象注入**: 原型污染和不安全的对象属性访问
- **时序攻击**: 敏感数据的非常量时间操作

### ESLint 配置

项目包含一个全面的 ESLint 配置（`.eslintrc.json`），具有专注安全规则和 `eslint-plugin-security` 插件，用于增强漏洞检测。

## 🛠️ 配置

### 环境变量
在项目根目录创建 `.env` 文件：
```bash
# OpenAI API 密钥（AI 分析需要）
OPENAI_API_KEY=your-openai-api-key-here

# 可选：自定义 OpenAI 基础 URL
OPENAI_BASE_URL=https://api.openai.com/v1
```

### 自定义分析规则
创建自定义 `config.json` 覆盖默认设置：
```json
{
  "analyzer": {
    "severity_threshold": "medium",
    "max_file_size": 2048,
    "concurrent_limit": 8
  },
  "security": {
    "allowed_file_extensions": [".py", ".js", ".jsx"],
    "blocked_patterns": ["*.min.js", "node_modules"]
  }
}
```

## 🔧 故障排除

### 常见问题

**找不到 ESLint**
```bash
# 全局安装 ESLint
npm install -g eslint eslint-plugin-security

# 或在项目中本地安装
npm install eslint eslint-plugin-security
```

**找不到 Python 模块**
```bash
# 确保在项目目录中且激活了虚拟环境
cd CodeSentinel
source venv/bin/activate  # Linux/macOS
# 或
venv\Scripts\activate     # Windows

# 重新安装依赖
pip install -r requirements.txt
```

**大型代码库的内存问题**
```bash
# 减少并发工作线程
python main.py src/ --workers 2

# 排除大目录
python main.py src/ --exclude "node_modules" --exclude ".git"
```

**AI 分析不工作**
1. 检查 `.env` 文件中的 OpenAI API 密钥
2. 验证 API 密钥有足够余额
3. 检查网络连接
4. 先尝试本地分析器：`--analyzer local`

### 调试模式
启用详细日志进行故障排除：
```bash
python main.py src/ --verbose --progress
```

## 🤝 贡献

我们欢迎贡献！请查看我们的[贡献指南](CONTRIBUTING.md)了解详情。

### 开发环境设置
```bash
# 克隆并安装开发依赖
git clone https://github.com/superFRANK666/CodeSentinel.git
cd CodeSentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # 开发依赖

# 运行测试
python -m pytest tests/

# 运行代码质量检查
flake8 src/
mypy src/
```

## 📄 许可证

本项目根据 MIT 许可证授权 - 详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- [ESLint](https://eslint.org/) - JavaScript 分析引擎
- [OpenAI](https://openai.com/) - AI 驱动的代码分析
- Python 安全社区的灵感和反馈

---

<div align="center">

**⭐ 如果这个项目对您有帮助，请给我们一个星标！**

[🐛 报告问题](https://github.com/superFRANK666/CodeSentinel/issues) | [💡 功能请求](https://github.com/superFRANK666/CodeSentinel/issues/new) | [📖 文档](https://github.com/superFRANK666/CodeSentinel/wiki)

</div>
