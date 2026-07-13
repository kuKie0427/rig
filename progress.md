# progress.md — Session Continuity Log

Source of truth for feature state is `feature_list.json`. This file
records timeline-style session entries (who did what, when, what
verification ran, what was deferred).

---

## 2026-07-13 (Asia/Shanghai) — Phase 1 ship session

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

## Deferred items

1. **Phase 2 (L1 alert intake)**: large feature (~7 new files +
   4 test files). Independent branch `feat/alert-intake-l1`.
   Should pull from current `main` after this commit.
2. **Phase 3 (audit log + replay)**: gated on Phase 2's
   incident_id decision; needs alembic decision (open Q2).
   Independent branch `feat/audit-log-replay`.
3. **Phase 4 (3 K8s profiles)**: independent branch
   `feat/k8s-profiles`.
4. **Phase 5 (ops_bench evaluations)**: independent branch
   `feat/ops-bench-evaluations`.
5. **`docs/ARCHITECTURE.md`, `docs/PRODUCT.md`**: not yet
   scaffolded; `DIRECTIONS.md` is currently playing that role.
   If user requests formal docs/ split, that's a separate feature.
6. **Workspace root `/Volumes/code/allAgent/AGENTS.md`** does not
   mention `forks/` as a sibling — noted earlier, left for a
   later workspace-hygiene pass.

## Repository state at end of session

```
$ git log --oneline --graph -10
* d13920b Merge pull request #4 from kuKie0427/feat/k8s-validation
|\
| *   70f238b Merge branch 'main' into feat/k8s-validation
| |\
| |/  
|/|   
* |   d2afdb6 Merge branch 'fix/conftest-llm-rig-shim' into main
|\ \  
| * | 75d09ef fix(llm): add llm_rig compatibility shim for upstream rebrand
|/ /  
| * 0da3d37 fix(tools): extend cilium-policy-import flag tolerance + test-name parity
| * 470375a fix(tools): harden k8s_validation against Oracle-flagged regression gaps
| * 693de8d feat(tools): add k8s_validation with allowlist / D1-D8 deny / N-of-M HITL
|/  
* fc49641 Initial import (rebranded)
```

Working tree clean. Phase 1 is on `main` (d13920b). PR #4 merged.
Conftest fix (d2afdb6) is on `main` ahead of Phase 1.

## Verification commands run

```
# Phase 1 module
uv run ruff check rig/tools/k8s_validation.py tests/test_k8s_validation.py rig/llm/llm_rig.py
  → All checks passed
uv run mypy rig/tools/k8s_validation.py tests/test_k8s_validation.py rig/llm/llm_rig.py
  → Success: no issues found in 3 source files
uv run pytest tests/test_k8s_validation.py -v
  → 152 passed
uv run pytest tests/test_k8s_validation.py tests/test_tools_shell_validation.py -q
  → 266 passed in 0.62s
uv run pytest tests/ --co
  → 7804 tests collected (was 0 before conftest fix)
```
