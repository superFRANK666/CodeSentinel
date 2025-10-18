# CodeSentinel GitHub Release 发布指南

## 🎯 发布选项对比

| 发布方式 | 目标用户 | 打包需求 | 文件大小 | 用户体验 |
|---------|---------|---------|---------|---------|
| **仅源代码** | 开发者 | ❌ 不需要 | 小 | 🔧 需要配置环境 |
| **源代码+可执行文件** | 所有用户 | ✅ 需要打包 | 大 | ⭐ 开箱即用 |

## 📋 推荐发布策略

**🌟 混合发布策略**（推荐）

1. **GitHub Release** - 包含源代码标签
2. **Assets** - 上传预编译的可执行文件
3. **文档** - 完整的安装和使用说明

### 🎯 为什么选择混合发布？

- ✅ **覆盖所有用户类型** - 开发者和普通用户都能使用
- ✅ **降低使用门槛** - 普通用户无需配置Python环境
- ✅ **保持开源透明** - 源代码完全可见可审计
- ✅ **专业形象** - 提供多种安装选项

## 🚀 完整发布流程

### 步骤1: 准备源代码

```bash
# 确保代码已提交
git status
git add .
git commit -m "Prepare for v1.0.0 release"
git push origin main
```

### 步骤2: 创建版本标签

```bash
# 创建带说明的标签
git tag -a v1.0.0 -m "Release v1.0.0: First stable release - AI-powered security auditor

## 主要特性
- Enterprise-grade architecture with dependency injection
- Multi-language support (Python & JavaScript)
- Advanced hybrid analysis engine (Static + AI)
- Enhanced CLI with beautiful ASCII art animations
- Docker support and CI/CD pipeline
- Comprehensive documentation in English and Chinese

## 性能优化
- SHA-256 based intelligent caching
- Parallel processing with configurable workers
- Memory optimization for large codebases
- Incremental analysis for CI/CD integration

## 安全增强
- Advanced vulnerability detection patterns
- Modern JavaScript framework support
- Privacy modes for sensitive code analysis
- Enhanced error handling and debugging support"

# 推送标签到GitHub
git push origin v1.0.0
```

### 步骤3: 生成可执行文件（可选但推荐）

```bash
# Windows用户
cd build
build_windows.bat

# Linux/macOS用户
cd build
chmod +x build_unix.sh
./build_unix.sh
```

### 步骤4: 创建发布包

```bash
# 生成发布文件
cd scripts
python create_release.py
```

### 步骤5: 在GitHub创建Release

1. **访问GitHub Release页面**
   ```
   https://github.com/superFRANK666/CodeSentinel/releases/new
   ```

2. **填写Release信息**
   - **Tag**: `v1.0.0`
   - **Title**: `Release v1.0.0: AI-Powered Security Auditor`
   - **Description**: 复制 `release/RELEASE_NOTES.md` 的内容

3. **上传Assets**
   - `CodeSentinel-Windows-x64.zip` (如果打包了)
   - 其他平台的可执行文件（如果有）

4. **发布Release**
   - 点击 "Publish release"

## 📦 文件结构说明

### GitHub Release Assets

```
Release v1.0.0/
├── CodeSentinel-Windows-x64.zip     # Windows独立可执行文件包
├── RELEASE_NOTES.md                 # 详细发布说明
└── manifest.json                   # 发布元数据
```

### ZIP包内容

```
CodeSentinel-Windows-x64.zip
├── CodeSentinel.exe                # 主程序
├── README.md                       # 使用说明
├── quick_start.bat                 # 快速启动脚本
└── .env.example                    # 环境变量示例
```

## 🔄 自动化发布（高级）

### GitHub Actions 自动发布

```yaml
# .github/workflows/release.yml
name: Create Release

on:
  push:
    tags:
      - 'v*'

jobs:
  create-release:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Windows executable
        run: |
          cd build
          build_windows.bat

      - name: Create Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          draft: false
          prerelease: false

      - name: Upload Release Asset
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ steps.create_release.outputs.upload_url }}
          asset_path: release/CodeSentinel-Windows-x64.zip
          asset_name: CodeSentinel-Windows-x64.zip
          asset_content_type: application/zip
```

## 📊 发布后检查清单

### ✅ 必要检查

- [ ] Release页面显示正确
- [ ] 所有Assets上传成功
- [ ] 可执行文件可以正常下载
- [ ] Release链接指向正确的标签
- [ ] 版本号一致

### 🔍 功能验证

- [ ] Windows可执行文件能正常运行
- [ ] 源代码安装脚本工作正常
- [ ] 文档链接正确指向新版本
- [ ] GitHub Actions CI/CD通过（如果有）

### 📈 发布后任务

- [ ] 在社交媒体/社区发布通知
- [ ] 更新项目网站（如果有）
- [ ] 发送邮件通知用户（如果有）
- [ ] 监控反馈和问题报告

## 🎯 用户安装体验

### Windows用户（推荐）

1. 访问GitHub Release页面
2. 下载 `CodeSentinel-Windows-x64.zip`
3. 解压并运行 `CodeSentinel.exe`
4. 按提示配置API密钥
5. 开始使用！

### 开发者用户

1. 克隆仓库：
   ```bash
   git clone https://github.com/superFRANK666/CodeSentinel.git
   cd CodeSentinel
   ```

2. 运行安装脚本：
   ```bash
   # Linux/macOS
   chmod +x scripts/setup.sh && ./scripts/setup.sh

   # Windows
   scripts\setup.bat
   ```

3. 开始使用：
   ```bash
   python main.py --help
   ```

## 📞 支持和维护

### 问题反馈

- **GitHub Issues**: [创建新问题](https://github.com/superFRANK666/CodeSentinel/issues/new)
- **功能请求**: [提交功能请求](https://github.com/superFRANK666/CodeSentinel/issues/new)
- **安全问题**: 私信或邮件报告

### 版本管理

- **语义化版本**: 遵循 SemVer 2.0.0
- **发布周期**: 根据功能开发和用户反馈
- **维护政策**: 长期维护，定期更新

---

**准备好发布你的第一个专业版本了吗？** 🚀

记住：一个好的Release不仅提供软件，还提供优秀的用户体验！