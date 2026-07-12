"""ACP (Agent Client Protocol) support for rig.

rig implements ACP in two roles:

- **Agent** (server side): ``rig-acp`` / ``python -m rig.acp`` exposes
  rig as an ACP-compatible agent that editors (Zed, JetBrains, …) can
  connect to.

- **Client** (client side): :class:`~rig.acp.client.RigAcpClient` lets
  rig spawn *other* ACP agents (including rig itself) as isolated
  subprocesses.  This is useful for per-session cwd isolation in the HTTP
  server and for multi-harness subagent support.
"""

from .agent import RigAgent
from .client import RigAcpClient, acp_client
from .types import (
    PermissionKind,
    PermissionOption,
    ToolCall,
    ToolCallStatus,
    ToolKind,
    rig_tool_to_acp_kind,
)

__all__ = [
    # Agent (server) side
    "RigAgent",
    # Client side
    "RigAcpClient",
    "acp_client",
    # Types
    "PermissionKind",
    "PermissionOption",
    "ToolCall",
    "ToolCallStatus",
    "ToolKind",
    "rig_tool_to_acp_kind",
]
