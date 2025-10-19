# CodeSentinel 安装指南

## 🚀 快速开始

### 方法1: 直接运行可执行文件（推荐）

1. 进入 `release/windows/` 目录
2. 运行 `CodeSentinel.exe`
3. 按照交互式界面提示操作

### 方法2: 源码安装

```bash
# 克隆仓库
git clone <repository-url>
cd CodeSentinel

# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py
```

## ⚙️ 配置要求

### 必需配置
- **Python 3.8+** - 基础运行环境

### 可选配置（用于AI分析功能）
- **OpenAI API密钥** - AI驱动分析需要
- **Node.js + ESLint** - JavaScript代码分析需要

## 📋 环境配置

1. 复制 `.env.example` 为 `.env`
2. 配置OpenAI API密钥（如需AI功能）：
   ```
   OPENAI_API_KEY=your-openai-api-key-here
   ```

## 🔧 系统要求

- **操作系统**: Windows 10/11 (64位), Linux, macOS
- **Python**: 3.8 或更高版本
- **内存**: 建议 4GB+
- **磁盘空间**: 100MB+

## 📦 依赖项

```txt
# 核心依赖
httpx>=0.24.0
pydantic>=2.0.0
PyYAML>=6.0
colorama>=0.4.0
tqdm>=4.60.0
psutil>=5.8.0
chardet>=4.0.0
aiofiles>=0.8.0
python-dotenv>=0.19.0
```

## 🎯 验证安装

```bash
# 显示版本信息
python main.py --version

# 显示帮助
python main.py --help

# 分析示例文件
python main.py your_script.py --analyzer local
```

## 🔍 故障排除

### 常见问题

1. **缺少依赖**: 运行 `pip install -r requirements.txt`
2. **权限问题**: 以管理员身份运行
3. **端口占用**: 检查默认端口是否被占用
4. **API密钥**: 确保 `.env` 文件配置正确

### 获取帮助

- 📖 查看详细文档: `docs/` 目录
- 💡 使用示例: `examples/` 目录
- 🐛 报告问题: GitHub Issues

---

🛡️ **CodeSentinel** - 智能代码安全审计工具
版本: 1.0.0 | 许可证: MIT