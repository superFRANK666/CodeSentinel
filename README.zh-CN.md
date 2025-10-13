<p align="right">[English](README.md)</p>

# CodeSentinel: AI 驱动的代码安全审计器

CodeSentinel 是一款先进的、由 AI 驱动的 Python 安全审计工具。它采用混合方法，将本地静态分析（AST、污点分析）与强大的 AI 模型（如 GPT-4o-mini）相结合，以提供深入、准确的漏洞检测。它是一个命令行工具，旨在帮助开发人员在代码进入生产环境之前识别和修复安全问题。

## 主要功能

- **混合分析引擎**: 结合了本地抽象语法树（AST）和污点分析的速度与 AI 模型的深度上下文理解能力。
- **多种分析器模式**: 可在 `local`、`ai` 或 `hybrid` 分析模式之间选择，以满足您对速度和准确性的需求。
- **全面的漏洞检测**: 识别各种安全漏洞，包括：
    - SQL 注入
    - 命令注入
    - 跨站脚本（XSS）
    - 不安全的反序列化
    - 硬编码的秘密和密钥
    - 弱加密
    - 路径遍历
- **多格式报告**: 生成清晰且可操作的报告，支持多种格式：`console`、`markdown`、`json`、`html` 和 `xml`。
- **智能缓存**: 缓存未更改文件的结果，以显著加快后续扫描速度。
- **用户友好的 CLI**: 功能丰富的命令行界面，提供广泛的选项以实现定制化的分析体验。
- **插件架构**: 设计了插件管理器，以便将来扩展检测器和报告器。

## 要求

- Python 3.10+
- 一个 OpenAI API 密钥（用于 `ai` 和 `hybrid` 模式）。

## 安装

1.  **克隆仓库：**
    ```bash
    git clone https://github.com/superFRANK666/CodeSentinel.git
    cd CodeSentinel
    ```

2.  **创建并激活虚拟环境（推荐）：**
    ```bash
    # 对于 Windows
    python -m venv venv
    venv\Scripts\activate

    # 对于 macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **安装依赖：**
    ```bash
    pip install -r requirements.txt
    ```

4.  **设置您的环境变量：**
    - 将 `docs` 目录下的示例文件 `.env.example` 复制到项目根目录，并重命名为 `.env`。
    - 打开 `.env` 文件并添加您的 OpenAI API 密钥：
        ```
        OPENAI_API_KEY=your-openai-api-key-here
        ```

## 用法

CodeSentinel 从命令行运行。以下是一些常见用法示例：

**1. 分析单个文件：**
```bash
python main.py path/to/your/file.py
```

**2. 分析整个目录：**
```bash
python main.py src/
```

**3. 生成特定格式的报告：**
```bash
# 生成 Markdown 报告
python main.py src/ --output report.md --format markdown

# 生成 HTML 报告
python main.py src/ --output report.html --format html
```

**4. 使用特定的分析器：**
```bash
# 仅使用快速的本地分析器
python main.py src/ --analyzer local

# 使用 AI 分析器进行深度扫描
python main.py src/ --analyzer ai
```

**5. 按严重性过滤并显示进度：**
```bash
python main.py src/ --severity high --progress
```

**6. 获取所有命令的帮助：**
```bash
python main.py --help
```

## 项目结构

项目采用清晰、分层的架构组织：

```
CodeSentinel/
├── config/                # 默认配置文件
├── docs/                  # 文档和示例
├── src/
│   ├── application/       # 核心应用逻辑（分析器、报告生成器）
│   ├── core/              # 核心组件（接口、容器、基类）
│   └── infrastructure/    # 支持模块（配置、缓存、UI 等）
├── .gitignore
├── main.py                # 主要的 CLI 入口点
├── requirements.txt       # 项目依赖
└── .env                   # 环境变量（由您创建）
```

## 配置

- **环境变量**: 配置秘密（如 OpenAI API 密钥）的主要方式是通过项目根目录中的 `.env` 文件。
- **JSON 配置**: 默认行为（如分析器设置、报告格式等）在 `config/default.json` 中定义。您可以创建一个自定义的 `config.json` 来覆盖这些设置。

## 贡献

欢迎贡献！如果您想做出贡献，请遵循以下步骤：

1.  Fork 本仓库。
2.  创建一个新分支 (`git checkout -b feature/your-feature`)。
3.  进行更改并提交 (`git commit -m 'Add some feature'>`)。
4.  推送到分支 (`git push origin feature/your-feature`)。
5.  开启一个 Pull Request。

## 许可证

本项目根据 MIT 许可证授权。
