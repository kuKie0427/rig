# rig

Terminal AI agent for ops. Three-tier command permission (allowlist / denylist / Human-in-the-Loop), process-group shell isolation, audit-trail-ready hooks.

Built for runbook-style operations: k8s / helm / DB inspection / log analysis. Designed so a destructive command (`kubectl delete`, `helm uninstall`, `DROP TABLE`) cannot reach the shell without explicit human approval, and an audit record of that approval exists.

## Design priorities

1. **Permission is first-class.** Every shell command passes through `allowlist` (auto-approve), `denylist` (hard-block), or `HITL` (per-call SSE-driven approval prompt). No raw `subprocess.run`. The `ShellSession` runs in its own process group (`start_new_session=True`) so timeouts kill the whole tree via `os.killpg`.
2. **Audit trail ready.** All confirmations, denials, approvals, and stdout/stderr are routed through hooks. Adding a sink (file / DB / S3) is one hook registration.
3. **Risk-aware tools.** Beyond binary `allow/deny`, hooks can carry N-of-M approval for high-risk commands (e.g., `kubectl delete`, `helm uninstall`, `DROP TABLE`).
4. **Subagent support via profiles.** Run a read-only inspector and a writable deployer in the same session with non-overlapping tool access.

## Install (dev)

```bash
poetry install
poetry run rig --help
```

For server mode (HTTP + SSE for human approvals):

```bash
poetry install --extras server
poetry run rig-server --port 5700
```

## Key directories

| Path | Purpose |
|---|---|
| `rig/tools/` | Tool definitions. `shell.py` and `shell_validation.py` are the allowlist/denylist source of truth. |
| `rig/cli/` | CLI commands (`rig`, `rig-server`, `rig-eval`, etc.) |
| `rig/llm/` | LLM provider integrations (Anthropic / OpenAI) |
| `rig/server/` | HTTP + SSE server driving the per-tool HITL flow |
| `rig/eval/` | Eval suites — extension point for ops-style benchmarks (danger-block rate, plan adherence, transfer-to-human recall) |
| `rig/hooks/` | Hook system — extension point for audit sinks, N-of-M approval |
| `tests/` | Test suite (pytest, xdist-parallelized) |

## Roadmap 二开 targets

- [ ] `rig/tools/k8s_validation.py` — port the 3-tier pattern to `kubectl` allow/deny lists (`get/describe/logs/top` auto-allow; `delete/uninstall/scale --replicas=0` hard-deny)
- [ ] `rig/hooks/audit/` — structured audit log writer (DB schema + WAL file for replay)
- [ ] `rig/hooks/n_of_m_approval.py` — multi-approver gate for destructive ops (e.g., 2/3 on-call approvers required)
- [ ] `rig/eval/ops_bench/` — eval suite covering (a) danger-block rate, (b) plan-adherence, (c) transfer-to-human recall
- [ ] Profiles: `read-only inspector` / `apply-only deployer` / `admin` as pre-defined subagent scopes

## License

MIT. See [LICENSE](LICENSE).
