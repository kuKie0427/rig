"""Compatibility shim for `rig.llm.llm_rig`.

This module preserves the original `rig.llm.llm_rig` import path after
the upstream rebrand that renamed `llm_rig.py` to `llm_gptme.py`. The
fork's `rig.init` and ~5 test files still import the old path:

    from rig.llm.llm_rig import RigAuthError
    from rig.llm.llm_rig import DEFAULT_SERVICE_URL, device_flow_authenticate

Touching every consumer would scatter rebrand-related churn across the
codebase. The shim keeps the public surface intact and is one file to
remove once every consumer has migrated.

When to remove: once `grep -rn "llm_rig" rig/ tests/` returns zero hits
across both `rig/` and `tests/`, this file can be deleted.
"""

from .llm_gptme import (
    _LEGACY_SERVICE_URLS,
    _SUPABASE_FUNCTIONS_V1,
    _SUPABASE_URL,
    _TOKEN_DIR,
    DEFAULT_BASE_URL,
    DEFAULT_DEVICE_AUTH_URL,
    DEFAULT_MODELS_BASE_URL,
    DEFAULT_SERVICE_URL,
    RigAuthError,
    _get_token_path,
    _load_token,
    _save_token,
    device_flow_authenticate,
    get_api_key,
    get_base_url,
    get_models_url,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_DEVICE_AUTH_URL",
    "DEFAULT_MODELS_BASE_URL",
    "DEFAULT_SERVICE_URL",
    "RigAuthError",
    "_LEGACY_SERVICE_URLS",
    "_SUPABASE_FUNCTIONS_V1",
    "_SUPABASE_URL",
    "_TOKEN_DIR",
    "_get_token_path",
    "_load_token",
    "_save_token",
    "device_flow_authenticate",
    "get_api_key",
    "get_base_url",
    "get_models_url",
]
