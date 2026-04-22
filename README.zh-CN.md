<p align="right"><a href="README.md">English</a></p>

# CodeSentinel v2.0.0

面向 Windows 的代码安全分析 CLI，强调确定性、可审计和 CI/CD 可集成。

## 核心能力

- 多语言扫描：Python、JavaScript、TypeScript（可扩展）
- 双模式分析：本地确定性分析 + 可选 AI 辅助分析
- Secret 扫描：模式、熵值与上下文联合检测
- 依赖风险扫描：manifest/lockfile 风险与策略支持
- 多格式输出：JSON、SARIF、Markdown、HTML、XML、控制台
- 增量扫描：基于文件哈希的差异扫描
- 策略引擎：严重级别/置信度阈值与 CI 策略配置
- 基线抑制：基于指纹的已知问题抑制
- 可移植退出码：适合自动化流水线

## 快速开始

```powershell
# 检查版本与环境
.\codesentinel.cmd spec-version
.\codesentinel.cmd doctor -Format json

# 扫描当前目录并输出 JSON
.\codesentinel.cmd scan . -Format json -Output report.json

# 启用 secrets + deps 并输出 SARIF
.\codesentinel.cmd scan . -Enable secrets,deps -Format sarif -Output report.sarif
```

## 安装与配置

1. 下载并解压发布包
2. 在 PowerShell 中进入目录
3. 运行 `.\codesentinel.cmd spec-version` 验证

如需 AI 分析：

1. 将 `.env.example` 复制为 `.env`
2. 填写 `OPENAI_API_KEY`

详细说明见 [INSTALLATION.md](INSTALLATION.md)。

## 架构分层

```text
codesentinel.cmd
  └─ codesentinel.ps1
       └─ CodeSentinel.exe
```

`codesentinel.ps1` 负责稳定 CLI 合约、配置合并、范围过滤、策略决策和输出标准化。

## 仓库目录说明

- `src/`：应用层、核心分析接口与基础设施实现
- `tests/`：单元与集成测试
- `test-fixtures/`：golden 样例与模拟扫描目标
- `docs/`：规范、架构说明、路线图与实现状态文档
- `schemas/`：报告、配置、策略、baseline、batch 清单等 JSON Schema
- `scripts/`：发布与环境初始化脚本
- `config/`：默认配置模板
- `rulepacks/` 与 `policies/`：内置规则索引与策略包
- `release/`：发布产物相关说明

## 常用命令

- `scan [target]`：执行扫描
- `doctor`：环境诊断
- `config-validate`：配置校验
- `spec-version`：输出规范版本
- `rules-list`：列出规则包
- `rules-pin`：写入规则锁定文件
- `baseline-create`：生成 baseline
- `batch-scan`：按清单执行组合扫描

## 退出码

- `0`：成功（无阻断）
- `10`：发现问题
- `11`：触发策略阻断
- `12`：部分结果（非完整覆盖）
- `20`：用法错误
- `30`：配置错误
- `40`：运行时错误
- `50`：依赖错误
- `60`：内部错误

## 文档入口

- [CLI 规范](docs/CLI_SPEC_v2.md)
- [实现状态](docs/IMPLEMENTATION_STATUS.md)
- [路线图](docs/ROADMAP.md)
- [变更日志](CHANGELOG.md)

## 许可证

[MIT](LICENSE)
