# PromptShield Agent

PromptShield Agent 是一个用于检查 AI Agent 项目的本地安全扫描工具。它会扫描项目中的 prompt、工具定义、配置文件和相关代码，发现常见的 prompt injection、危险工具权限和密钥管理风险，并生成 Markdown 报告。

## 功能特性

- 扫描本地 AI Agent 项目文件
- 检测 prompt injection 和 jailbreak 风险
- 检测危险工具权限，例如 shell 执行、文件删除、联网外传
- 检测疑似硬编码密钥
- 输出终端摘要、JSON 结果和 Markdown 报告
- 提供交互式命令行 UI
- 支持离线模式
- 可选支持 DeepSeek/OpenAI-compatible function calling 编排

## 环境要求

- Python 3.10 或更高版本
- 无必需第三方依赖

## 安装

克隆项目后进入仓库目录：

```bash
cd promptshield-agent
```

可直接使用模块方式运行：

```bash
python -m promptshield --version
```

也可以安装为本地开发包：

```bash
pip install -e .
```

安装后可直接使用命令：

```bash
promptshield --version
```

## 使用方法

扫描示例项目：

```bash
python -m promptshield scan examples/vulnerable_agent
```

指定报告输出路径：

```bash
python -m promptshield scan examples/vulnerable_agent -o scan-report.md
```

输出 JSON：

```bash
python -m promptshield scan examples/vulnerable_agent --json
```

查看工具 schema：

```bash
python -m promptshield list-tools
```

启动交互式命令行 UI：

```bash
python -m promptshield ui
```

在 Windows 新 PowerShell 窗口中启动交互式 UI：

```bash
python -m promptshield launch-ui
```

## DeepSeek 配置

PromptShield 默认使用离线模式，不需要 API key。

如果需要启用 DeepSeek function calling 编排，请通过环境变量配置：

```powershell
$env:DEEPSEEK_API_KEY="your-real-key-here"
$env:DEEPSEEK_API_BASE="https://api.deepseek.com"
$env:DEEPSEEK_MODEL="your-model-name"
python -m promptshield scan examples/vulnerable_agent --llm
```

如果需要确认 API 必须接入成功，可以加上 `--require-llm`。这样在 API key、网络或模型配置有问题时会直接失败，而不是回退到离线模式：

```powershell
python -m promptshield scan examples/vulnerable_agent --llm --require-llm
```

交互式 UI 也支持 DeepSeek 模式：

```powershell
python -m promptshield ui --llm --require-llm
```

不要把真实 API key 写入源码、文档或任何公开材料。仓库中的 `.env.example` 只用于说明可配置项。

## 项目结构

```text
promptshield-agent/
  .github/
    workflows/
      ci.yml            # GitHub Actions CI
  docs/
    assignment-report.md # 课程作业报告草稿
  promptshield/
    agent.py            # Agent 编排逻辑
    cli.py              # 命令行入口
    deepseek_client.py  # DeepSeek/OpenAI-compatible API 客户端
    report.py           # 报告生成
    rules.py            # 风险检测规则
    schemas.py          # 数据结构
    tools.py            # 工具定义与调用
    ui.py               # 交互式命令行界面
  examples/
    vulnerable_agent/   # 示例待扫描项目
  tests/
    test_rules.py       # 单元测试
  CONTRIBUTING.md       # 贡献指南
  SECURITY.md           # 安全报告说明
```

## 测试

运行测试：

```bash
python -m unittest
```

或显式指定测试目录：

```bash
python -m unittest discover -s tests
```

## 隐私说明

- 离线模式不会把文件内容发送到外部服务。
- LLM 模式只发送目标路径和工具调用摘要。
- 详细扫描证据和报告在本地生成。
- `.gitignore` 已忽略 `.env`、`.env.*` 和本地生成的扫描报告。

## License

MIT
