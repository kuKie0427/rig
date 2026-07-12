"""
DSPy integration for rig prompt optimization.

This module provides tools for automatically optimizing rig's system prompts
using DSPy's prompt optimization techniques like MIPROv2 and BootstrapFewShot.
"""

import importlib.util
from functools import lru_cache

from .cli import main

__all__ = ["main"]


@lru_cache
def _has_dspy() -> bool:
    """Check if DSPy is available."""
    return importlib.util.find_spec("dspy") is not None
