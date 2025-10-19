<p align="right"><a href="README.md">English</a></p>

# 🛡️ CodeSentinel v1.0.0: 智能代码安全审计工具

<div align="center">

![Version](https://img.shields.io/badge/version-v1.0.0-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)](https://python.org)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?style=for-the-badge&logo=javascript)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![License](https://img.shields.io/badge/license-MIT-red?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen?style=for-the-badge)

**🔍 智能代码安全审计工具 - 保护您的代码安全**

CodeSentinel 是一款专业的代码安全审计工具，结合了本地静态分析、AI驱动的深度检测和行业标准的漏洞识别技术，为现代代码库提供全面的安全保障。

</div>

## ✨ 核心特性

### 🔍 多语言支持
- **Python**: 完整的AST分析、污点分析和AI驱动的深度检测
- **JavaScript**: ESLint集成，支持React、Vue等现代框架
- **自动识别**: 智能检测文件类型，选择合适的分析器
- **大文件处理**: 针对大型代码库的内存优化分析器

### 🛡️ 全面的漏洞检测
- **注入攻击**: SQL注入、命令注入、代码注入等
- **Web安全**: XSS、CSRF、路径遍历、原型污染
- **加密问题**: 弱算法、不安全随机数、时序攻击
- **数据泄露**: 硬编码密钥、敏感数据泄露模式
- **JavaScript特有**: eval()使用、不安全动态代码、对象注入
- **现代威胁**: 检测最新的安全漏洞和攻击向量

### 🚀 性能与易用性
- **智能缓存**: 基于SHA-256的文件缓存，显著提升重复扫描速度
- **并行处理**: 可配置的工作线程数量，支持并发分析
- **多格式报告**: Console、Markdown、JSON、HTML、XML格式输出
- **实时进度**: 动态UI显示分析进度和状态
- **交互式界面**: 友好的用户界面，支持交互式操作

### 💡 智能分析引擎
- **混合分析**: 结合AST/Taint分析速度与AI深度检测优势
- **多种分析模式**: `local`(本地)、`ai`(AI)、`hybrid`(混合)、`multi_language`(多语言)
- **增量分析**: 只分析变更文件，完美适配CI/CD流程
- **漏洞优先级**: 智能评估漏洞严重程度和修复建议

## 🚀 快速开始

### 安装要求

- **Python 3.8+** - 基础运行环境
- **Node.js + ESLint** - JavaScript分析（可选）

### 安装方法

#### 方法1: 使用可执行文件（推荐）

1. 下载 `CodeSentinel.exe`
2. 双击运行或命令行执行
3. 按照交互式界面提示操作

#### 方法2: 源码安装

```bash
# 克隆仓库
git clone <repository-url>
cd CodeSentinel

# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py
```

## 📋 使用指南

### 基础用法

```bash
# 分析单个文件
python main.py script.py                    # Python文件
python main.py app.js                       # JavaScript文件

# 分析目录（自动检测文件类型）
python main.py src/                         # 混合语言
python main.py frontend/                    # JavaScript/TypeScript
python main.py backend/                     # Python
```

### 高级用法

```bash
# 使用特定分析器
python main.py src/ --analyzer local        # 本地分析（快速）
python main.py src/ --analyzer ai           # AI分析（深度）
python main.py src/ --analyzer hybrid       # 混合分析
python main.py src/ --analyzer multi_language  # 多语言分析（默认）

# 过滤漏洞严重程度
python main.py src/ --severity high         # 仅高危漏洞
python main.py src/ --severity critical     # 仅严重漏洞

# 生成报告
python main.py src/ --output report.html   # HTML报告
python main.py src/ --output report.json    # JSON报告
python main.py src/ --format xml --output security.xml  # XML报告

# 显示进度和详细信息
python main.py src/ --progress --verbose
```

### 交互式模式

```bash
# 启动交互式界面
python main.py

# 然后按照菜单提示操作：
# 1. 📁 分析代码文件或目录
# 2. 📖 显示详细帮助信息
# 3. ⚙️ 配置设置
# 4. 📊 查看配置状态
# 5. ❓ 使用示例
# 0. 🚪 退出程序
```

## ⚙️ 配置

### 环境变量配置

1. 复制 `.env.example` 为 `.env`
2. 配置相关设置：

```bash
# OpenAI API密钥（AI功能需要）
OPENAI_API_KEY=your-openai-api-key-here

# 默认分析器
ANALYZER_TYPE=multi_language

# 日志级别
LOG_LEVEL=INFO
```

### 配置选项

- `OPENAI_API_KEY`: OpenAI API密钥（AI分析功能）
- `OPENAI_MODEL`: AI模型选择（默认: gpt-4o-mini）
- `ANALYZER_TYPE`: 默认分析器类型
- `CACHE_ENABLED`: 是否启用缓存（默认: true）
- `MAX_FILE_SIZE`: 最大文件大小限制（KB）
- `CONCURRENT_LIMIT`: 并发分析数量

## 📊 报告格式

### 控制台输出
```bash
python main.py src/ --format console
```

### HTML报告
```bash
python main.py src/ --output report.html --format html
```

### JSON报告
```bash
python main.py src/ --output report.json --format json
```

### XML报告
```bash
python main.py src/ --output report.xml --format xml
```

## 🛠️ 安全特性

### 数据保护
- **隐私模式**: 多级隐私保护，防止敏感数据泄露
- **本地分析**: 无需网络连接，数据完全本地处理
- **配置加密**: 敏感配置信息加密存储

### API安全
- **密钥保护**: 不硬编码API密钥，支持环境变量配置
- **连接加密**: HTTPS加密传输
- **访问控制**: 支持API访问限制和认证

## 🔧 技术架构

### 分层架构
- **应用层**: 用户界面、业务逻辑
- **核心层**: 分析器、配置管理、缓存系统
- **基础设施层**: 错误处理、日志、缓存、认证

### 设计模式
- **依赖注入**: 清晰的组件解耦
- **策略模式**: 可插拔的分析器设计
- **观察者模式**: 进度和状态通知

### 性能优化
- **智能缓存**: SHA-256文件指纹缓存
- **并行处理**: 多线程并发分析
- **内存管理**: 大文件内存优化

## 📁 项目结构

```
CodeSentinel/
├── main.py                    # 主程序入口
├── src/                       # 源代码
│   ├── core/                 # 核心模块
│   │   ├── analyzers/        # 分析器
│   │   ├── interfaces/       # 接口定义
│   │   └── container/       # 依赖注入容器
│   ├── application/          # 应用层
│   └── infrastructure/       # 基础设施
├── docs/                      # 详细文档
├── examples/                  # 使用示例
├── requirements.txt           # Python依赖
├── .env.example              # 环境变量模板
├── .eslintrc.json           # ESLint配置
├── .flake8                   # Python代码风格
└── LICENSE                   # MIT许可证
```

## 🧪 支持的语言和框架

### Python
- **版本**: Python 3.8+
- **框架**: Django, Flask, FastAPI 等
- **检测**: AST分析、污点跟踪、模式匹配

### JavaScript
- **版本**: ES6+ (ES2015+)
- **框架**: React, Vue.js, Angular, Express 等
- **检测**: ESLint集成、安全规则检查

## 📈 性能指标

### 分析速度
- **小文件** (< 1KB): < 100ms
- **中等文件** (1-10KB): < 500ms
- **大文件** (> 10KB): < 2s

### 内存使用
- **基础分析**: < 50MB
- **AI分析**: < 200MB
- **大文件处理**: 优化的流式处理

### 缓存效果
- **重复扫描**: 90%+ 时间节省
- **增量分析**: 只分析变更文件

## 🔍 漏洞检测类型

### 注入攻击
- SQL注入
- 命令注入
- 代码注入
- NoSQL注入
- LDAP注入

### Web安全
- 跨站脚本攻击 (XSS)
- 跨站请求伪造 (CSRF)
- 路径遍历
- 文件包含
- HTTP头部注入

### 加密问题
- 弱加密算法
- 不安全随机数
- 时序攻击
- 密钥管理问题

### 数据保护
- 硬编码密钥
- 敏感数据泄露
- 不安全存储
- 日志注入

### JavaScript特有
- eval() 和 Function() 构造函数
- 原型污染
- 全局对象污染
- 动态代码执行

## 📚 文档

- **[INSTALLATION.md](INSTALLATION.md)** - 详细安装指南
- **[docs/](docs/)** - API文档和架构说明
- **[examples/](examples/)** - 使用示例和最佳实践
- **[CHANGELOG.md](CHANGELOG.md)** - 版本更新日志

## 🤝 贡献指南

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

### 开发环境设置
```bash
# 克隆仓库
git clone <repository>
cd CodeSentinel

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/mac
# 或 venv\Scripts\activate  # Windows

# 安装开发依赖
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 运行测试
```bash
# 运行所有测试
pytest

# 运行测试并生成覆盖率报告
pytest --cov=src tests/
```

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 🆘 获取帮助

- 📖 **文档**: 查看 `docs/` 目录
- 💡 **示例**: 查看 `examples/` 目录
- 🐛 **问题反馈**: GitHub Issues
- 📧 **邮件**: support@codesentinel.dev

---

**🛡️ CodeSentinel v1.0.0** - 您的代码安全守护者

*保护代码安全，从每一次分析开始*