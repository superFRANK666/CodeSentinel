# CodeSentinel v2.0.0 Release Guide

本指南用于维护主仓库的 v2.0.0 正式发布流程。

## 发布前检查

1. 工作区干净：`git status`
2. 版本一致：
   - `README.md`
   - `README.zh-CN.md`
   - `pyproject.toml`
   - `codesentinel.ps1`
   - `codesentinel.config.json`
   - `codesentinel.rules.lock.json`
3. 基础校验通过：

```powershell
.\codesentinel.cmd spec-version
.\codesentinel.cmd config-validate -ErrorFormat json
pytest tests/unit
```

## 创建发布提交与标签

```bash
git add .
git commit -m "release: prepare v2.0.0"
git tag -a v2.0.0 -m "CodeSentinel v2.0.0"
```

## 推送到 GitHub

```bash
git push origin master
git push origin v2.0.0
```

## 生成发布资产

仓库内置脚本会在 `release/` 下生成发布压缩包与清单：

```bash
python scripts/create_release.py
```

生成文件：

- `release/CodeSentinel-Windows-v2.0.0.zip`
- `release/manifest.json`
- `release/RELEASE_NOTES.md`

## 在 GitHub 创建 Release

1. 打开：`https://github.com/superFRANK666/CodeSentinel/releases/new`
2. 选择 Tag：`v2.0.0`
3. Title：`CodeSentinel v2.0.0`
4. Description：使用 `RELEASE_NOTES.md` 内容
5. 上传 `release/` 目录下生成的资产并发布

## 发布后核验

- Release 页面显示 tag/version 正确
- 下载压缩包并校验 `CodeSentinel.exe` 可执行
- `checksums.txt` 与发布资产一致
- `spec-version` 输出 `2.0.0`