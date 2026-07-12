# rig-acp

ACP (Agent Client Protocol) entry point for [rig](https://github.com/rig/rig).

This is a thin shim package that allows rig to be listed in the [ACP agent registry](https://github.com/agentclientprotocol/registry) and launched via `uvx`, enabling agent discovery in editors like Zed and JetBrains.

## Usage

### Quick start (no install required)

```bash
uvx rig-acp
```

### Persistent install

```bash
pipx install rig-acp
rig-acp
```

## What this package does

`rig-acp` is a minimal wrapper that:

1. Declares `rig[acp]` as its dependency (pulls in rig + the `agent-client-protocol` library)
2. Exposes `rig-acp` as its default executable — the ACP server that editors connect to

The agent communicates with editors via JSON-RPC over stdio using the ACP protocol.

## ACP Agent Registry

This package exists so rig can be listed in the [ACP agent registry](https://github.com/agentclientprotocol/registry):

```json
{
  "package": "rig-acp",
  "launch": {"type": "uvx"}
}
```

The registry powers agent discovery in Zed, JetBrains, and other ACP-compatible editors. Without this package, the registry cannot launch rig because:

- `uvx rig` runs the interactive CLI, not the ACP server
- `uvx --from 'rig[acp]' rig-acp` requires `--from`, a shape the registry cannot express
- Extras-qualified specs like `rig[acp]` fail the registry's package-existence check

## Configuration

The ACP agent uses rig's standard configuration (`~/.config/rig/config.toml`). API keys are read from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.).

## Documentation

Full ACP documentation: https://rig.org/docs/acp.html
