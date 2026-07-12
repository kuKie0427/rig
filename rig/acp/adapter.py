"""Adapter layer for converting between rig and ACP types.

This module provides bidirectional conversion between:
- rig Message <-> ACP Content
"""

from __future__ import annotations

from typing import Literal

from ..message import Message


def rig_message_to_acp_content(msg: Message) -> list[dict]:
    """Convert a rig Message to ACP Content blocks.

    Args:
        msg: rig Message to convert

    Returns:
        List of ACP Content dictionaries (TextContent format)
    """
    content = []

    # Add main text content
    if msg.content:
        text = msg.content
        content.append(
            {
                "type": "text",
                "text": text,
            }
        )

    return content


RoleType = Literal["system", "user", "assistant"]


def acp_content_to_rig_message(content: list, role: RoleType) -> Message:
    """Convert ACP Content blocks to a rig Message.

    Handles both dict content blocks and Pydantic model instances
    (e.g. TextContentBlock from the ACP SDK).

    Args:
        content: List of ACP Content blocks (dicts or Pydantic models)
        role: Message role ("system", "user", or "assistant")

    Returns:
        rig Message instance
    """
    text_parts = []

    for c in content:
        # Support both dict-style access and Pydantic model attribute access
        if isinstance(c, dict):
            if c.get("type") == "text":
                text_parts.append(c.get("text", "") or "")
        else:
            # Pydantic model (e.g. TextContentBlock)
            if getattr(c, "type", None) == "text":
                text_parts.append(getattr(c, "text", "") or "")

    return Message(role=role, content="\n".join(text_parts))
