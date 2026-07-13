# AGENTS.md

rig is a fork of `gptme` (Erik Bjäreholt, MIT) rebranded for K8s platform
teams. Phase 1 implements `DIRECTIONS.md § Phase 1`: 7 K8s CLI families
× allowlist of 12 subcommands + D1-D8 deny dimensions + N-of-M
risk_level → approver mapping, all in `rig/tools/k8s_validation.py`.

Locked planning: `DIRECTIONS.md` — 5 sequential phases (Phase 1:
k8s_validation; Phase 2: L1 alert intake; Phase 3: audit log + replay;
Phase 4: K8s profiles; Phase 5: ops_bench evaluations). Phase 1 is
shipped. Phases 2-5 are queued behind Pre-flight D1-D4 (deployment,
GitHub OAuth, PagerDuty approver pool, fallback) which are already
locked in the planning doc.

This fork's two primary upstream-deltas:
1. K8s tool validation gated by a 3-tier HITL permission model
   (allowlist / denylist / N-of-M approver).
2. Upstream-name compat shim `rig/llm/llm_rig.py` so the fork's
   `rig.init` and existing tests can import the renamed
   `llm_gptme.py` without scattered rebrand churn.

## Startup Workflow

Before writing code:

1. **Confirm working directory** with `pwd`
2. **Read this file** completely
3. **Read `DIRECTIONS.md`** (the planning doc IS the architecture +
   product spec for this fork; `docs/` is not yet scaffolded)
4. **Read `feature_list.json`** to see current feature state
5. **Review recent commits** with `git log --oneline -10`

If baseline verification is failing, repair that first before adding new scope.

## Working Rules

- **One feature at a time**: Pick exactly one unfinished feature from
  `feature_list.json`. Do not bundle Phases.
- **Verification required**: Don't claim done without running verification
  commands and recording pass/fail.
- **Update artifacts before ending session**: `progress.md` and
  `feature_list.json` must reflect actual state, not aspirational state.
- **Stay in scope**: Don't modify files unrelated to the current
  feature. Cross-cutting concerns (e.g. conftest fix) get their own
  branch + their own PR.
- **Prefer `git merge --no-ff`** for branch integration. Linear history
  is hostile to a multi-phase plan that needs each phase recoverable.
- **Conventional Commits** per existing AGENTS.md conventions:
  `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## Required Artifacts

- `AGENTS.md` (this file) — agent SOP
- `DIRECTIONS.md` — planning doc (architecture / product spec)
- `feature_list.json` — Feature state tracker (source of truth)
- `progress.md` — Session continuity log

Optional:
- `session-handoff.md` — Reserved for larger sessions that span
  many turns / contexts. Not currently used.

## Definition of Done

A feature is done only when ALL of the following are true:

- [ ] Target behavior is implemented in the feature's intended location
- [ ] Required verification actually ran (`uv run pytest`,
      `uv run ruff check`, `uv run mypy`)
- [ ] New / modified public API documented in the module / class
      docstring (Python convention; ruff ignores E501 etc. for docstrings)
- [ ] Evidence recorded in `feature_list.json` or `progress.md`
      (pass counts, ruff/mypy/pytest outcomes)
- [ ] Repository remains restartable from standard startup path
      (no new uncommitted state required to make tests pass)
- [ ] If crossing the source / test boundary, both files are staged
      together (one PR, one merge commit when feasible)

## End of Session

Before ending a session:

1. Update `progress.md` with current state (what landed, what's open)
2. Update `feature_list.json` with new feature status
3. Record any unresolved risks or blockers (Pre-flight 🟡 items, etc.)
4. Commit with descriptive message once work is in safe state
5. Leave repo clean: no uncommitted scratch files, no orphan
   branches, no agents_md / feature_list drift

## Verification Commands

Full verification (recommended):

```bash
uv run pytest tests/test_k8s_validation.py tests/test_tools_shell_validation.py -v
```

Required checks (in any order):

```bash
# Tests — focused
uv run pytest tests/test_k8s_validation.py -v
uv run pytest tests/test_tools_shell_validation.py -v

# Tests — full suite
uv run pytest tests/ -q

# Lint
uv run ruff check rig/ tests/

# Type-check
uv run mypy rig/tools/k8s_validation.py tests/test_k8s_validation.py

# All-in-one (matches CI)
make precommit
```

## Escalation

If you encounter:

- **Architecture decisions** (e.g. Phase 2 webhook contract, Phase 3
  schema): consult `DIRECTIONS.md` first. If still ambiguous, ask
  user. Do NOT default to a design decision on your own — every
  Phase is reviewed by Oracle per `harness-engineering` workflow.
- **Unclear requirements**: `DIRECTIONS.md` § 关键开放问题 lists
  pre-known open questions. L1-9 are L1-specific; L1-5 are scoping
  decisions documented but not yet locked.
- **Repeated test failures**: Update `progress.md`, mark feature as
  `blocked` in `feature_list.json`, and request human review.
- **Scope ambiguity**: Re-read `feature_list.json` definition of done
  for the current feature. If still ambiguous, split the feature into
  two adjacent smaller ones rather than expanding scope silently.

## Cross-cutting Operational Notes

- `rig/llm/llm_rig.py` is a rebrand compatibility shim — DO NOT
  delete without first running `grep -rn llm_rig rig/ tests/` and
  migrating every consumer to `rig.llm.llm_gptme`.
- `tests/conftest.py` imports `rig.init`. After the upstream gptme
  → rig rebrand, conftest collection fails without the shim. Keep
  the shim in lockstep with `llm_gptme.py`'s public surface.
- Container runtime (docker / containerd / runc / crictl / ctr /
  nerdctl) is HARD-OOS per `DIRECTIONS.md` L47. The
  `k8s_validation.py` regex set intentionally does not match these.
- Locked deployment shape (from Pre-flight D1-D4 in `DIRECTIONS.md`):
  shared single-instance rig-server + SQLite (Phase 3 may upgrade
  to Postgres); GitHub OAuth for SSO; PagerDuty-sourced approver
  pool with 5-min refresh; single-on-call fallback to 2/2 + escalate.
