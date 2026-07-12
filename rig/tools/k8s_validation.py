"""K8s command validation and safety checks for `rig`.

Phase 1 of DIRECTIONS.md. Ports the three-tier permission pattern
(allowlist / denylist / N-of-M HITL) from `shell_validation.py` to seven
K8s CLI families: kubectl, helm, cilium (incl. ciliumctl), istioctl,
argocd, flux (incl. fluxctl), plus the special `kubectl krew` sub-case.

This module is a *pure validation library*. It does not register any
hooks, mutate any state, or talk to the LLM. Phase 1 deliberately ends
at the boundary `classify_k8s_command` — Phase 2 (L1 alert intake)
wires it into the diagnostic pipeline; Phase 3 (audit + replay) wires
it into the N-of-M gate.

Known limitations (Phase 1, documented for follow-up):
    - Only un-prefixed commands are detected. `sudo kubectl ...`,
      `KUBECONFIG=foo kubectl ...`, `bash -c "kubectl ..."` all
      short-circuit to the vacuous-decision path. Flag/value disambiguation
      uses a simple "first non-flag token is subcommand" rule; the rare
      case where a flag value (e.g. `-n get`) collides with a known
      subcommand name falls back to the default HITL medium path, which
      is the safe default.
    - `deny_dimension` priorities are order-sensitive in `DENY_GROUPS`:
      the most-specific dimension (e.g. D7 `kubectl exec`) is checked
      before broader patterns (e.g. D1 `kubectl delete`). New dimensions
      must be inserted at the right priority slot.

Reference: DIRECTIONS.md § Phase 1 (lines ~88-128).
"""

import logging
import re
import shlex
from dataclasses import dataclass
from typing import Literal

from .shell_validation import (
    _find_heredoc_regions,
    _find_quotes,
    _is_in_quoted_region,
)

logger = logging.getLogger(__name__)


Action = Literal["allow", "hitl", "deny"]
RiskLevel = Literal["low", "medium", "high"]


# `ciliumctl` and `fluxctl` are alias binary names; both are listed so
# the lookup is a single frozenset membership test. `kubectl krew` is
# NOT a member of this set — its first token is `kubectl`, so the
# special case is handled in `classify_k8s_command`.
FAMILIES: frozenset[str] = frozenset(
    {"kubectl", "helm", "cilium", "ciliumctl", "istioctl", "argocd", "flux", "fluxctl"}
)


# A subcommand may be 1- or 2-token deep. 1-token entries are bare
# strings; 2-token entries (e.g. argocd "app get", kubectl "auth can-i")
# are stored as tuples so the matcher can do an exact depth-correct
# comparison. Tuple entries take precedence over string entries in
# `_classify_subcommand`.
ALLOWLISTED_SUBCOMMANDS: dict[str, list[str | tuple[str, ...]]] = {
    "kubectl": [
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        ("rollout", "status"),
        ("auth", "can-i"),
    ],
    "helm": [
        "list",
        "search",
        "status",
    ],
    "cilium": [
        "get",
        "describe",
        "endpoint",
        ("identity", "get"),
    ],
    "ciliumctl": [
        "get",
        "describe",
        "endpoint",
        ("identity", "get"),
    ],
    "istioctl": [
        "analyze",
        "describe",
    ],
    "argocd": [
        ("app", "get"),
        ("app", "list"),
        ("app", "logs"),
    ],
    "flux": [
        "get",
        "list",
    ],
    "fluxctl": [
        "get",
        "list",
    ],
    # `kubectl krew install` is NOT allowlisted; it triggers D5 medium.
    "krew": [
        "search",
    ],
}


# Each tuple: (dimension_label, [regex_patterns], human_reason).
# Iteration order is PRIORITY — most-specific dimension first. Re-order
# only with care: see module docstring "Known limitations".
#
# Risk level per dimension is encoded in `RISK_LEVEL_BY_DIMENSION` below.
# `--force` and ClusterRole-pattern escalations for D1 / D5 are handled
# by `_should_escalate_to_high`.
DENY_GROUPS: list[tuple[str, list[str], str]] = [
    (
        "D7",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:exec|cp|port-forward|proxy)\b",
        ],
        "[D7] lateral-movement access (exec/cp/port-forward/proxy): required 3/3 approver",
    ),
    (
        "D6",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:namespace|ns)\b",
        ],
        "[D6] namespace deletion: required 3/3 approver + 30s lock",
    ),
    (
        "D5",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+auth\s+reconcile\b",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+apply\b",
            r"(?<![\w-])argocd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+app\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sync(?![\w-])",
            r"(?<![\w-])flux\b(?:\s+--?\S+(?:\s+\S+)?)*\s+reconcile(?![\w-])",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+krew\b(?:\s+--?\S+(?:\s+\S+)?)*\s+install\b",
        ],
        "[D5] privileged RBAC / GitOps sync / krew install / kubectl apply: required 2/3 approver (3/3 if --force or ClusterRole modify)",
    ),
    (
        "D4",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+drain\b",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cordon\b",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+taint\s+nodes?\b[^\n;&|]*NoSchedule-",
        ],
        "[D4] node drain / cordon / taint eviction: required 2/3 approver",
    ),
    (
        "D3",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+scale\b[^\n;&|]*--replicas(?:\s*=|\s+)0\b",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+rollout\b(?:\s+--?\S+(?:\s+\S+)?)*\s+undo\b",
        ],
        "[D3] scale-to-zero / rollout undo: required 2/3 approver",
    ),
    (
        "D2",
        [
            r"\bhelm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:uninstall|delete)\b",
            r"\bcilium\b(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+import\b",
            r"(?<![\w-])istioctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+install(?![\w-])",
        ],
        "[D2] helm uninstall / cilium policy import / istioctl install: required 2/3 approver",
    ),
    (
        "D8",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+edit\b",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+debug\b",
        ],
        "[D8] schemaless edit / ephemeral debug: required 2/3 approver",
    ),
    (
        # D1: kubectl delete (broadest). Checked LAST so that the
        # more-specific dimensions above win for overlapping patterns
        # (e.g. `kubectl delete ns foo` matches D6 first, not D1).
        "D1",
        [
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
        ],
        "[D1] kubectl delete op: required 2/3 approver (3/3 if --force --grace-period=0)",
    ),
]


# Static default per dimension. See DIRECTIONS.md § Phase 1 § HITL.
RISK_LEVEL_BY_DIMENSION: dict[str, RiskLevel] = {
    "D1": "medium",
    "D2": "medium",
    "D3": "medium",
    "D4": "medium",
    "D5": "medium",
    "D6": "high",
    "D7": "high",
    "D8": "medium",
}


# ClusterRole modification is `high` per DIRECTIONS.md § Phase 1 § HITL.
_CLUSTERROLE_ESCALATION_PATTERN = re.compile(r"cluster\S*role", re.IGNORECASE)


# Read by callers to compose the `N-of-M` approval gate. Phase 1
# surfaces only this lookup; Phase 3 wires the actual gate.
REQUIRED_APPROVALS_BY_RISK: dict[RiskLevel, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


# `--force` flag — token-boundary anchored so `--force-with-lease`
# (a "safer force" idiom, even though K8s doesn't currently use it)
# would not match. Keeps the regex narrow.
_FORCE_FLAG_PATTERN = re.compile(r"--force(?:[\s=]|$)")


@dataclass(frozen=True)
class K8sCommandDecision:
    """Structured verdict returned by `classify_k8s_command`.

    All fields are populated eagerly. Non-K8s commands yield an `allow`
    verdict with `is_k8s_command=False` and every optional field None —
    the classifier never claims authority over non-K8s shell traffic.
    """

    action: Action
    risk_level: RiskLevel | None
    is_k8s_command: bool
    family: str | None
    subcommand: tuple[str, ...] | None
    deny_dimension: str | None
    matched_text: str | None
    reason: str | None


def classify_k8s_command(command: str) -> K8sCommandDecision:
    """Classify a shell command by K8s family and policy verdict.

    Returns a `K8sCommandDecision` whose `action` is one of:
      - `"allow"`: K8s read-only allowlist match → auto-confirm.
      - `"hitl"`: K8s command requiring human-in-the-loop approval
                  (deny dimensions D1-D8, or non-allowlisted write-class).
      - `"deny"`: Reserved for future phases; never emitted in Phase 1.

    Non-K8s commands (e.g. `ls`, `git status`, `echo hi`) yield an
    `allow` verdict with `is_k8s_command=False`. This module does not
    claim authority over non-K8s shell traffic — that's
    `shell_validation`'s job.
    """
    if not command or not command.strip():
        return _vacuous_decision()

    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unbalanced quote / bad escape — fall back to whitespace split
        # rather than raising. We deliberately do not classify malformed
        # input to deny: better to err on the safe default-hitl-medium.
        tokens = command.split()

    if not tokens or not tokens[0]:
        return _vacuous_decision()

    first = tokens[0]

    # Special case: `kubectl krew <subcmd>`. First two tokens must be
    # exactly `kubectl krew`; the family label is `krew` and the
    # remaining tokens form the subcommand.
    if first == "kubectl" and len(tokens) >= 3 and tokens[1] == "krew":
        family = "krew"
        rest: list[str] = list(tokens[2:])
    elif first in FAMILIES:
        family = first
        rest = list(tokens[1:])
    else:
        return _vacuous_decision()

    # Deny check (highest priority). Done against the original string
    # with quote / heredoc regions excluded so that e.g.
    # `echo 'kubectl delete foo'` and `cat << EOF\nkubectl delete foo\nEOF`
    # never trigger a false D1 hit.
    deny_dimension, matched_text = _match_deny_group(command)
    if deny_dimension is not None:
        risk_level: RiskLevel = RISK_LEVEL_BY_DIMENSION[deny_dimension]
        if _should_escalate_to_high(command, deny_dimension):
            risk_level = "high"
        sub = _extract_subcommand(rest)
        return K8sCommandDecision(
            action="hitl",
            risk_level=risk_level,
            is_k8s_command=True,
            family=family,
            subcommand=sub,
            deny_dimension=deny_dimension,
            matched_text=matched_text,
            reason=_reason_for_dimension(deny_dimension),
        )

    allowlisted, sub = _classify_subcommand(family, rest)
    if allowlisted:
        return K8sCommandDecision(
            action="allow",
            risk_level="low",
            is_k8s_command=True,
            family=family,
            subcommand=sub,
            deny_dimension=None,
            matched_text=None,
            reason=None,
        )

    # K8s family detected but neither allowlisted nor in any deny
    # dimension. Conservative default: HITL medium (deployer-class
    # write op). Catches `kubectl apply foo.yaml`, `helm upgrade --install
    # my-release`, `argocd app delete my-app` and similar — the broad
    # class of K8s write operations that DIRECTIONS.md § Phase 1 § HITL
    # maps to medium N-of-M.
    return K8sCommandDecision(
        action="hitl",
        risk_level="medium",
        is_k8s_command=True,
        family=family,
        subcommand=sub,
        deny_dimension=None,
        matched_text=None,
        reason=(
            f"{family} command not in allowlist; default HITL medium "
            "(2/3 approver) per DIRECTIONS.md § Phase 1 HITL mapping"
        ),
    )


def is_k8s_allowlisted(command: str) -> bool:
    """True iff `command` is a K8s read-only allowlisted command."""
    decision = classify_k8s_command(command)
    return decision.action == "allow" and decision.is_k8s_command


def is_k8s_denylisted(command: str) -> tuple[bool, str | None, str | None]:
    """True iff `command` triggers HITL approval (i.e. needs human review).

    Phase 1 never auto-denies a K8s command outright — every gate is HITL.
    This function exists for symmetry with
    `rig.tools.shell_validation.is_denylisted` and downstream hook wiring
    in Phase 3, but the semantic is "needs HITL approval", not
    "denied outright".

    Returns:
        (True, reason, matched_text) for HITL-bound commands,
        (False, None, None) for vacuous / allowlisted / non-K8s commands.
    """
    decision = classify_k8s_command(command)
    if not decision.is_k8s_command or decision.action == "allow":
        return False, None, None
    return True, decision.reason, decision.matched_text


def required_approvals_for(risk_level: RiskLevel) -> int:
    """Number of approvers required for a given risk level (default N=3 pool)."""
    return REQUIRED_APPROVALS_BY_RISK[risk_level]


def _vacuous_decision() -> K8sCommandDecision:
    """Return value for empty / non-K8s inputs — vacuous allow."""
    return K8sCommandDecision(
        action="allow",
        risk_level=None,
        is_k8s_command=False,
        family=None,
        subcommand=None,
        deny_dimension=None,
        matched_text=None,
        reason=None,
    )


def _extract_subcommand(rest_tokens: list[str]) -> tuple[str, ...] | None:
    """Return the first 1-2 non-flag tokens after the family prefix.

    Flag-value disambiguation is heuristic: a token starting with `-`
    is treated as a flag, and the next token (if any, and not itself
    starting with `-`) is treated as the flag's value and skipped too.
    This handles `-n namespace`, `--namespace prod`, but falsely
    consumes values for compound boolean flags like `-it`. The
    resulting misclassification falls through to the default
    HITL-medium path, which is the safe default.
    """
    non_flag: list[str] = []
    i = 0
    while i < len(rest_tokens) and len(non_flag) < 2:
        tok = rest_tokens[i]
        if tok.startswith("-"):
            # Embedded value form (`--key=val`) — skip one.
            if "=" in tok:
                i += 1
                continue
            # Possible value-follows form (`-n ns`); consume next token
            # only if it doesn't look like another flag. Heuristic.
            if i + 1 < len(rest_tokens) and not rest_tokens[i + 1].startswith("-"):
                i += 2
            else:
                i += 1
            continue
        non_flag.append(tok)
        i += 1
    return tuple(non_flag) if non_flag else None


def _classify_subcommand(
    family: str, rest_tokens: list[str]
) -> tuple[bool, tuple[str, ...] | None]:
    """Return `(allowlisted, subcommand_tuple)` for the family-prefix remainder."""
    entries = ALLOWLISTED_SUBCOMMANDS.get(family, [])
    sub = _extract_subcommand(rest_tokens)
    if not sub:
        return False, None
    if not entries:
        return False, sub

    # Prefer 2-token match (e.g. argocd "app get") so that broad 1-token
    # subcommands like "app" don't shadow the more-specific 2-token
    # entries below.
    if len(sub) >= 2:
        two = (sub[0], sub[1])
        for entry in entries:
            if isinstance(entry, tuple) and entry == two:
                return True, sub
    one = sub[0]
    for entry in entries:
        if isinstance(entry, str) and entry == one:
            return True, sub
    return False, sub


def _match_deny_group(command: str) -> tuple[str | None, str | None]:
    """Return `(dimension_label, matched_text)` for highest-priority deny.

    Iterates `DENY_GROUPS` in priority order (most-specific first) and
    returns the first dimension whose regex matches outside any quoted
    region or heredoc region. This is why `kubectl exec` reports D7
    (lateral-movement) rather than D1 (delete) — D7 is checked first.
    """
    if not command or not command.strip():
        return None, None

    safe_regions = _find_quotes(command) + _find_heredoc_regions(command)

    for dimension, patterns, _reason in DENY_GROUPS:
        for pattern in patterns:
            match = re.search(pattern, command)
            if match is not None and not _is_in_quoted_region(match.start(), safe_regions):
                return dimension, match.group(0)

    return None, None


def _has_force_flag(command: str) -> bool:
    """Return True if `--force` is present in `command` outside quotes / heredocs."""
    safe_regions = _find_quotes(command) + _find_heredoc_regions(command)
    for match in _FORCE_FLAG_PATTERN.finditer(command):
        if not _is_in_quoted_region(match.start(), safe_regions):
            return True
    return False


def _should_escalate_to_high(command: str, dimension: str) -> bool:
    """True if D1 / D5 should escalate from base risk to high for this command.

    Escalation rules (DIRECTIONS.md § Phase 1 § HITL):
    D1: --force. D5: --force OR ClusterRole pattern (matching outside
        quotes / heredocs — `kubectl apply 'clusterrole.yaml'` is NOT
        a real ClusterRole modify).
    D7 / D6 are already high unconditionally; D2 / D3 / D4 / D8 do not
    escalate under Phase 1.
    """
    if dimension == "D1":
        return _has_force_flag(command)
    if dimension == "D5":
        if _has_force_flag(command):
            return True
        safe_regions = _find_quotes(command) + _find_heredoc_regions(command)
        for match in _CLUSTERROLE_ESCALATION_PATTERN.finditer(command):
            if not _is_in_quoted_region(match.start(), safe_regions):
                return True
        return False
    return False


def _reason_for_dimension(dimension: str) -> str:
    """Return the human-readable reason registered for `dimension` in `DENY_GROUPS`."""
    for d, _, reason in DENY_GROUPS:
        if d == dimension:
            return reason
    return ""
