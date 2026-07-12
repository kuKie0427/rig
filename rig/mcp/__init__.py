from .client import MCPClient
from .registry import (
    MCPRegistry,
    MCPServerInfo,
    format_server_details,
    format_server_list,
)

__all__ = [
    "MCPClient",
    "MCPRegistry",
    "MCPServerInfo",
    "format_server_details",
    "format_server_list",
    "RigMCPServer",
    "create_server",
]


def __getattr__(name: str):
    # Lazy-import server symbols so that `from rig.mcp import MCPClient`
    # does NOT trigger loading rig.mcp.server (which imports the full tools
    # package). Only import the server module when explicitly requested.
    if name in ("RigMCPServer", "create_server"):
        from .server import RigMCPServer, create_server

        if name == "RigMCPServer":
            return RigMCPServer
        return create_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
