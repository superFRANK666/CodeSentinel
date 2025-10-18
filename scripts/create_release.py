#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Release 创建工具
自动生成Release所需的文件和描述
"""

import os
import sys
import subprocess
import json
from pathlib import Path
import hashlib

def calculate_file_hash(file_path):
    """计算文件的SHA256哈希值"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def get_file_size(file_path):
    """获取文件大小的可读格式"""
    size_bytes = os.path.getsize(file_path)
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"

def create_release_notes():
    """创建Release说明"""
    return '''## 🎉 CodeSentinel v1.0.0 Released!

**AI-Powered Multi-Language Code Security Auditor**

### 🚀 Major Features

- **Enterprise-Grade Architecture**: Clean layered design with dependency injection
- **Multi-Language Support**: Python and JavaScript with comprehensive security analysis
- **Advanced Analysis Engine**: Hybrid static analysis + AI-powered deep inspection
- **Enhanced CLI**: Beautiful ASCII art animations and intuitive user experience
- **Docker Support**: Multi-stage builds and development environment
- **Privacy Protection**: Enhanced privacy modes for sensitive code analysis
- **Performance Optimized**: Intelligent caching, parallel processing, incremental analysis

### 📋 Downloads

#### 🔧 Windows Users (Recommended)
- **CodeSentinel-Windows-x64.exe**: Self-contained executable, no installation required
- **System Requirements**: Windows 10/11 (64-bit)
- **Features**: Full functionality including AI analysis (requires OpenAI API key)

#### 🐧 Linux Users
- **Source Code**: Clone repository and run installation script
- **System Requirements**: Python 3.10+, Node.js 16+ (for JavaScript analysis)
- **Quick Install**: `chmod +x scripts/setup.sh && ./scripts/setup.sh`

#### 🍎 macOS Users
- **Source Code**: Clone repository and run installation script
- **System Requirements**: Python 3.10+, Node.js 16+ (for JavaScript analysis)
- **Quick Install**: `chmod +x scripts/setup.sh && ./scripts/setup.sh`

### 🛠️ Quick Start

#### Windows
1. Download `CodeSentinel-Windows-x64.exe`
2. Run the executable
3. Configure OpenAI API key when prompted
4. Start analyzing your code!

#### Linux/macOS
```bash
git clone https://github.com/superFRANK666/CodeSentinel.git
cd CodeSentinel
chmod +x scripts/setup.sh
./scripts/setup.sh
./CodeSentinel --help
```

### 🔍 What's New

#### 🚀 First Stable Release Features
- **Complete Architecture Overhaul**: Enterprise-grade clean architecture
- **Enhanced Security Analysis**: Advanced vulnerability detection patterns
- **Modern Development Toolchain**: pyproject.toml, Makefile, automated testing
- **Professional Documentation**: Comprehensive guides in English and Chinese
- **CI/CD Pipeline**: Automated testing, building, and deployment
- **Container Support**: Docker with multi-stage builds
- **Performance Boost**: 50%+ faster analysis with intelligent caching

#### 🛡️ Security Improvements
- Enhanced detection of injection attacks, XSS, and crypto vulnerabilities
- Support for modern JavaScript frameworks (React, Vue, Angular)
- Improved AI-powered analysis with better context understanding
- Privacy modes for sensitive code analysis

#### ⚡ Performance Enhancements
- SHA-256 based intelligent file caching
- Parallel processing with configurable worker limits
- Memory optimization for large codebases
- Incremental analysis for CI/CD integration

### 📚 Documentation

- [📖 README](https://github.com/superFRANK666/CodeSentinel/blob/main/README.md) - Getting started guide
- [🇨🇳 中文文档](https://github.com/superFRANK666/CodeSentinel/blob/main/README.zh-CN.md) - Chinese documentation
- [🛠️ Build Guide](https://github.com/superFRANK666/CodeSentinel/blob/main/BUILD.md) - Build from source
- [🤝 Contributing](https://github.com/superFRANK666/CodeSentinel/blob/main/CONTRIBUTING.md) - Contribution guidelines

### 🔐 Security Notice

This tool is designed for **defensive security analysis only**. It helps identify and fix security vulnerabilities in your code. Please use responsibly and in accordance with applicable laws and regulations.

### 🙏 Acknowledgments

- [OpenAI](https://openai.com/) - AI-powered code analysis
- [ESLint](https://eslint.org/) - JavaScript security analysis engine
- [Python AST](https://docs.python.org/3/library/ast.html) - Abstract syntax tree parsing
- The Python security community for inspiration and feedback

---

**⭐ Star this repository if it helped you!**

[🐛 Report Issues](https://github.com/superFRANK666/CodeSentinel/issues) | [💡 Feature Requests](https://github.com/superFRANK666/CodeSentinel/issues/new) | [📖 Documentation](https://github.com/superFRANK666/CodeSentinel/wiki)
'''

def main():
    """主函数"""
    print("🚀 CodeSentinel Release Creation Tool")
    print("=" * 50)

    project_root = Path(__file__).parent.parent
    release_dir = project_root / "release"
    windows_dir = release_dir / "windows"

    print(f"📁 Project root: {project_root}")
    print(f"📁 Release directory: {release_dir}")

    # 检查Windows可执行文件
    windows_exe = windows_dir / "CodeSentinel.exe"
    if not windows_exe.exists():
        print("❌ Windows executable not found!")
        print("Please run build_windows.bat first to create the executable.")
        return 1

    print(f"✅ Found Windows executable: {windows_exe}")

    # 创建打包文件
    release_files = []

    # Windows可执行文件信息
    exe_size = get_file_size(windows_exe)
    exe_hash = calculate_file_hash(windows_exe)

    print(f"📊 Windows executable:")
    print(f"   Size: {exe_size}")
    print(f"   SHA256: {exe_hash}")

    # 创建ZIP包
    import zipfile
    zip_path = release_dir / "CodeSentinel-Windows-x64.zip"
    print(f"📦 Creating Windows ZIP package: {zip_path}")

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # 添加可执行文件
        zipf.write(windows_exe, "CodeSentinel.exe")

        # 添加配置文件
        config_files = [
            (windows_dir / "README.md", "README.md"),
            (windows_dir / "quick_start.bat", "quick_start.bat"),
            (windows_dir / ".env.example", ".env.example"),
        ]

        for src, dst in config_files:
            if src.exists():
                zipf.write(src, dst)
                print(f"   + {dst}")

    zip_size = get_file_size(zip_path)
    zip_hash = calculate_file_hash(zip_path)
    print(f"   Size: {zip_size}")
    print(f"   SHA256: {zip_hash}")

    # 创建发布说明文件
    release_notes_path = release_dir / "RELEASE_NOTES.md"
    with open(release_notes_path, 'w', encoding='utf-8') as f:
        f.write(create_release_notes())

    print(f"📄 Release notes created: {release_notes_path}")

    # 生成文件清单
    manifest = {
        "version": "1.0.0",
        "release_date": subprocess.check_output(['date', '+%Y-%m-%d']).decode().strip(),
        "files": [
            {
                "name": "CodeSentinel-Windows-x64.zip",
                "size": zip_size,
                "sha256": zip_hash,
                "platform": "Windows",
                "architecture": "x64",
                "type": "executable"
            }
        ],
        "requirements": {
            "Windows": "Windows 10/11 (64-bit)",
            "Linux": "Python 3.10+, Node.js 16+ (optional)",
            "macOS": "Python 3.10+, Node.js 16+ (optional)"
        },
        "changelog": "Complete enterprise-grade overhaul with enhanced security analysis, modern architecture, and professional documentation."
    }

    manifest_path = release_dir / "manifest.json"
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

    print(f"📋 Release manifest created: {manifest_path}")

    print("\n" + "=" * 50)
    print("🎉 Release preparation complete!")
    print("=" * 50)
    print()
    print("📦 Files ready for GitHub Release:")
    print(f"   • CodeSentinel-Windows-x64.zip ({zip_size})")
    print(f"   • RELEASE_NOTES.md (Release description)")
    print(f"   • manifest.json (Release metadata)")
    print()
    print("🌐 Next steps:")
    print("1. Push your code to GitHub:")
    print("   git push origin main")
    print("   git push origin v1.0.0")
    print()
    print("2. Create GitHub Release:")
    print("   • Visit: https://github.com/superFRANK666/CodeSentinel/releases/new")
    print("   • Tag: v1.0.0")
    print("   • Title: Release v1.0.0")
    print("   • Description: Copy content from RELEASE_NOTES.md")
    print("   • Upload: CodeSentinel-Windows-x64.zip")
    print()
    print("🎯 Your release will be ready for all users!")

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)