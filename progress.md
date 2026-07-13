# progress.md — Session Continuity Log

Source of truth for feature state is `feature_list.json`. This file
records timeline-style session entries (who did what, when, what
verification ran, what was deferred).

---

## 2026-07-13 — Phase 2 L1 alert intake ship session (PR #6, OPEN)

**Operator**: Sisyphus (orchestrator) on behalf of user.

**Feature**: phase-2-l1-alert-intake — DIRECTIONS.md § Phase 2.

**Branch**: `feat/alert-intake-l1` off `main` (PR #6 OPEN)

### What was built

Phase 2 — L1 alert intake subsystem. Implements DIRECTIONS.md § Phase 2
verbatim: webhook normalization from 3 sources, LLM-driven read-only
diagnosis double-gated by Phase-1's `k8s_validation.allowlist`, and
multi-channel report distribution.

Files created (8 source, 4 test, 1 schema, 1 helper module):

```
rig/alert/__init__.py           public API surface
rig/alert/intake.py             AlertEvent + 3 normalizers + dedup + _IncidentRegistry
rig/alert/diagnostic.py         _propose_commands + _gate + _render_markdown + record_*
rig/alert/report.py             4 emit channels (chat/Slack/SMTP/PagerDuty)
rig/alert/schema.sql            alert_events + diagnostic_reports + l1_violations tables
rig/alert/schema.py             SCHEMA_SQL loader from schema.sql
rig/server/alerts_api.py        Flask blueprint with 3 endpoints
rig/server/app.py               alerts_api registered (modified — 2 lines added)

tests/test_alert_intake.py      14 tests
tests/test_alert_dedup.py       9 tests
tests/test_alert_diagnostic.py  14 tests
tests/test_alert_report.py      10 tests
```

### Implementation decisions (locked)

1. `AlertEvent` is `@dataclass(frozen=True)`. `with_incident()`
   helper produces a copy with a new `incident_id`.
2. `_IncidentRegistry` uses `closed_incidents: dict[key -> original_id]`
   so close->reopen restores the original incident_id rather than minting
   one prefixed by source.
3. Module-level `_DEFAULT_REGISTRY` so follow-up webhooks in the same
   process share dedup state automatically. Tests that need isolation
   pass an explicit `_IncidentRegistry()`.
4. `k8s_validation.allowlist` is the source of truth for the gate;
   `shell_allowlist_hook` is consulted for shell-only diagnostic
   commands (e.g. `ls /tmp`) — the dual-check interpretation per
   DIRECTIONS.md § Phase 2 step 3.
5. LLM mock uses `rig.message.Message("user", prompt)` with
   `mock/static` model. JSON parse failure of canned response is
   silently caught -> empty plan.
6. `l1_violations` table persists rejected commands with their
   deny_dimension so Phase 3's `rig replay` can surface them.
7. Schema version locked at schema.sql's mtime; bump + add a
   migration before changing column types (commented in file).

### Bugs found by tests during implementation

These were REAL bugs the Phase 2 PR fixed before merge:

1. `_gate` had a broken `shell_allowlist` logic. The original
   `dual_pass` check required `k8s_validation.action == "allow"` AND
   (`shell_allowlist_agrees` or `decision.family is None`). Since
   `shell_allowlist.is_allowlisted("kubectl get pods")` is always
   False, this rejected even allowlisted kubectl commands. Fixed:
   rework the gate to a clean rule (allowlisted K8s -> run;
   non-K8s with shell allowlist -> run; otherwise violation).
2. `_IncidentRegistry.closed_incidents` was typed `set[str]` but
   checked with tuple keys. Fixed: type -> `dict[tuple, str]`.
3. Datadog tag parser dropped tag values that lacked a colon
   (`extra` -> skipped). Fixed: tag-without-colon -> `labels[tag] = "true"`
   consistent with the list-input path.
4. `dedup` reopen caused duplicated source prefix
   (`alertmanager:am:g1:KubePodCrashLooping`). Fixed: restore the
   stored incident_id from `closed_incidents[key]`.

### Verification

```
ruff check rig/alert/ rig/server/alerts_api.py rig/server/app.py \
        tests/test_alert_intake.py tests/test_alert_dedup.py \
        tests/test_alert_diagnostic.py tests/test_alert_report.py
  -> All checks passed

mypy rig/alert/ rig/server/alerts_api.py \
        tests/test_alert_intake.py tests/test_alert_dedup.py \
        tests/test_alert_diagnostic.py tests/test_alert_report.py
  -> Success: no issues found in 10 source files

pytest tests/test_alert_*.py -q
  -> 50 passed in 6.16s

combined with Phase 1:
  -> 316 passed in 6.37s (zero regressions)
```

### Commit

`4d4bd6c feat(alert): Phase 2 L1 webhook intake + diagnostic report`
(13 files changed, +2070 / -14)

PR: `https://github.com/kuKie0427/rig/pull/6` (OPEN)

---

## 2026-07-13 — Agent SOP rewrite session (PR #5, merged)

Replaced fork-upstream `AGENTS.md` (verbatim gptme rebrand with stale
URLs) with template-driven SOP. Created `feature_list.json` (7
features tracked) and this `progress.md`. Branch `docs/agent-sop-update`
-> PR #5 merged as commit `f08cdc9`.

---

## 2026-07-13 — Phase 1 ship session (historical)



**Operator**: Sisyphus (orchestrator) on behalf of user.

**Pre-state**:
- Single upstream import commit `fc49641` on `main`
- DIRECTIONS.md staged for the first time (396 lines, 5 phases)
- README.md rebrand diff already present

### Session 1 — Phase 1 v1 (initial implementation)

- Created branch `feat/k8s-validation` per DIRECTIONS.md Phase 1 § 第一步 git 流程
- Wrote `rig/tools/k8s_validation.py` (484 LOC) and
  `tests/test_k8s_validation.py` (563 LOC, 100 tests, 19 classes)
- Verified: `ruff check` clean, `mypy` clean, `pytest` 100 pass
- Discovered and fixed real bugs:
  - D6 regex: `kubectl delete ns production` initially missed
    because the regex required `\s+` between `delete` and `ns`;
    fixed to `(?:--?\S+\s+)*` flag-tolerance
  - D3 regex: `--replicas 0` (space, no `=`) missed; loosened to
    `(?:\s*=|\s+)`
  - D4 regex: `kubectl taint nodes node1 key=value:NoSchedule-`
    backtracking-failed due to trailing `\b`; dropped
  - `is_k8s_allowlisted` initially returned True for non-K8s
    commands (vacuous allow); added `is_k8s_command` guard
- Committed as `693de8d`

### Session 2 — Oracle verification (loop iteration 2/500)

- Oracle on Phase 1 v1 returned VERDICT: PARTIAL with 8 gaps:
  1. Global flag bypass in deny regex (`kubectl --context prod exec`
     fell to D1 / medium)
  2. ClusterRole modification should escalate to high, not medium
  3. `cilium policy import` and `istioctl install` missing from D2
  4. Tests quantity (100 of 150 target)
  5-8. Out of scope for Phase 1 (D6 30s lock, conftest upstream bug,
     no production caller yet, README/DIRECTIONS touch)
- Iterated with Oracle twice (v2 then v3); closed 6 substantive gaps.
  3 orchestrator-judged out-of-scope deferred to later phases.

### Session 3 — Phase 1 v2 (Oracle-flagged fixes)

- All D1-D8 deny regexes extended with shared fragment
  `(?:\s+--?\S+(?:\s+\S+)?)*` to accept `--context X`,
  `--kubeconfig Y`, `-n Z` etc. between command verbs
- D5 broad-ified to include `kubectl apply` (clusterrole escalation
  handled separately by `_should_escalate_to_high`)
- New `_CLUSTERROLE_ESCALATION_PATTERN` (= case-insensitive
  `cluster\S*role`) — when matched OUTSIDE quotes/heredocs,
  escalates D5 from medium to high (per DIRECTIONS.md § Phase 1
  § HITL `high: 3/3 ... 含 ClusterRole 修改`)
- Added D2 analogues: `cilium policy import`, `istioctl install`
- `_should_escalate_to_high` extracted: respects quote/heredoc safe
  regions for ClusterRole pattern (NOT for `--force` which is
  always a force escalation regardless of quoting)
- Test count: 100 → 152. Added 7 new test classes covering
  global-flag tolerance, ClusterRole escalation, D2 analogues,
  edge cases
- Committed as `470375a`

### Session 4 — Phase 1 v3 (residual fix + naming)

- Oracle round 3 flagged: cilium D2 regex lacks flag-tolerance
  (other D2 patterns have it); fixed
- Two test methods renamed with `_limitation` suffix for naming
  parity with the krew heuristic-limit test
- Test count: 151 → 152
- Committed as `0da3d37`

### Session 5 — Final Oracle verification

- Oracle returned VERDICT: COMPLETE, `<promise>VERIFIED</promise>`
- 152 tests pass; 0 false positives verified; 0 regressions
- Phase 1 v3 certified
- `<promise>DONE</promise>` emitted at this checkpoint

### Session 6 — Conftest upstream bug fix (cross-cutting)

- Conftest fix identified as blocker for `make test` (relied on
  `--noconftest` workaround)
- Created `fix/conftest-llm-rig-shim` branch off `main`
- Wrote `rig/llm/llm_rig.py` (54 LOC, 16 re-exported symbols
  via `__all__`)
- Decision: compatibility shim (vs renaming llm_gptme → llm_rig)
  to keep rebrand churn localized to one file
- Module docstring documents removal criterion
- Committed as `75d09ef`

### Session 7 — Merge into main + push

- Locally merged `fix/conftest-llm-rig-shim` → `main`
  (merge commit `d2afdb6`, --no-ff)
- Locally merged `main` → `feat/k8s-validation`
  (merge commit `70f238b`, --no-ff) so Phase 1 reviews see the
  full test suite, not --noconftest
- Sandbox firewall initially blocked push (curl/nc/`git push`
  all timed out at github.com:443). Retried after network recovered.
- Pushed `main` (d2afdb6), then `feat/k8s-validation` (70f238b)
- Created PR #4 via `gh pr create --body-file`
- PR auto-collected clean: 7804 tests, +1361 lines across 2 files
- Merged PR #4 (`gh pr merge 4 --merge --delete-branch`); merge
  commit `d13920b` on main
- Cleaned up local branches; fetched remote state synced

### Session 8 — Agent SOP rewrite (this session)

- Created AGENTS.md replacing fork-upstream AGENTS.md (which still
  linked to rig.org/docs URLs after the rebrand)
- Created feature_list.json with current feature state (Phase 1
  and conftest fix done; Phases 2-5 pending)
- Created this progress.md
- Updated pre-flight status table from DIRECTIONS.md to enable
  cross-session tracking

---

## 2026-07-13 (Asia/Shanghai) — Phase 1 ship session
