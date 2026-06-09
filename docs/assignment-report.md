# PromptShield 作业报告草稿

## 1. Agent 目标

PromptShield 是一个面向 AI Agent 项目的安全检查助手。它的单一任务是扫描本地 agent 仓库中的 system prompt、tool schema、配置文件和相关代码，发现 prompt injection、工具滥用、危险权限和密钥管理风险。

这个方向对应课程 PPT 中的 AI Testing and Security、prompt injection、tool misuse 和 AI agent attack vectors。它不是依赖大模型基础知识直接判断，而是通过本地文件扫描、规则匹配、工具权限分析和报告生成等外部工具完成任务。

## 2. 架构设计

PromptShield 使用标准 function calling 风格的工具接口。核心 agent 只负责任务编排，实际能力由工具完成。

工具包括：

1. `scan_local_files`：读取本地 prompt、配置、代码和 tool schema 文件。
2. `detect_prompt_injection_patterns`：检查忽略上级指令、泄露密钥、jailbreak 等风险。
3. `analyze_tool_permissions`：检查 shell 执行、删除/写入文件、联网、缺少审批等工具风险。
4. `generate_security_report`：生成 Markdown 安全报告。

默认模式是 offline deterministic mode，保证没有 API key 时也可以稳定演示。可选的 `--llm` 模式使用 DeepSeek/OpenAI-compatible chat completions 和 tool schema，让模型通过 function calling 编排工具。

## 3. Context Integration

PromptShield 的上下文来自本地文件系统，而不是模型记忆。`scan_local_files` 会读取本地 agent 项目的 prompt、配置和工具定义；后续工具基于这些真实上下文生成 findings。

为了保护隐私，LLM 模式只向模型发送工具调用摘要，不发送完整文件内容。详细证据和报告在本地生成。

## 4. 运行截图安排

截图 1：运行交互式 UI。

```bash
python -m promptshield ui
```

截图 2：展示扫描结果页中的 Tool Calling Trace，证明 agent 调用了多个工具。

截图 3：展示 `promptshield-report.md` 中的 Severity Summary 和 Findings。

截图 4：可选，使用 `--llm --require-llm` 展示 DeepSeek function calling 编排成功。

## 5. AI 开发反思草稿

开发中遇到的一个具体技术问题是：最初的设计容易把 LLM 编排和本地扫描内容混在一起。如果把完整文件内容都作为 tool result 返回给模型，虽然实现简单，但会带来隐私风险，也不适合开源项目。

解决方式是把工具结果拆成两层：一层是给模型看的 `public_summary`，只包含文件数量、风险数量等摘要；另一层是本地 `ScanSession`，保存详细文件内容、证据行和 findings。这样 DeepSeek 在 `--llm` 模式中仍然能通过 function calling 编排工具，但敏感上下文不会被直接发送到模型提供商。

另一个问题是离线模式和 API 模式的扫描结果本来会一致，因为底层检测规则相同。为了让演示更清楚，最终在输出中加入了 `Orchestration`、`LLM used` 和 tool-call source，例如 `[offline]`、`[deepseek]`、`[fallback]`，并增加 `--require-llm` 来确认 API 必须接入成功。

## 6. 提交内容

- 代码仓库：包含 agent 主循环、tool definitions、规则检测、CLI 和交互式 UI。
- 报告：不超过 5 页，加入 3-4 张运行截图。
- README：说明如何运行、如何配置 DeepSeek API key，以及不要提交真实密钥。

