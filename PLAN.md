# Implementation Plan for Task 11

## Task
Strictly enforce `BLACKLIST` policy by disabling interactive user overrides, based on task 11 in `TODO.md`, while keeping `REQUIREMENTS.md` and `TEST-CASES.md` aligned.

## Goal
Make blacklisted path protection non-bypassable at runtime for all monitored tool flows:
- `bash` commands that target blacklisted paths
- file I/O tools: `read`, `write`, and `edit`

At the same time, preserve the existing interactive approval flow for dangerous bash commands that do **not** target blacklisted paths.

## Final Implementation Plan

### 1. Change runtime behavior for blacklisted `bash` path access
**File:** `safety-guard/handlers.ts`

Planned changes:
- Update the `handleBashTools()` branch that handles `findBlacklistedPathInCommand(...)` matches.
- Remove the interactive confirmation path for blacklisted bash path access.
- Make blacklisted bash path access return a block result immediately in both:
  - interactive mode
  - non-interactive mode
- Preserve the existing blacklisted-path detection logic itself; only the decision outcome changes.
- Preserve the existing dangerous-command flow for commands that are dangerous but do not target a blacklisted path.

Expected behavior after change:
- `cat ~/.ssh/id_rsa` → blocked immediately
- `cat .env` (when resolved into project blacklist scope) → blocked immediately
- `helm uninstall rel` → still requires interactive confirmation when UI is available

### 2. Change runtime behavior for blacklisted file I/O paths
**File:** `safety-guard/handlers.ts`

Planned changes:
- Update the `handleFileIOTools()` `securityLevel === "BLOCK"` branch.
- Remove the interactive confirmation path for blacklisted file I/O access.
- Make `read`, `write`, and `edit` return a block result immediately whenever the resolved path matches `BLACKLIST`, regardless of UI availability.
- Keep the existing behavior unchanged for:
  - whitelisted paths → auto-allow
  - non-whitelisted, non-blacklisted paths → interactive consent in UI / block in headless mode
  - path traversal detection
  - missing input no-op behavior

Expected behavior after change:
- `read ~/.ssh/config` → blocked immediately
- `write .env` inside project tree → blocked immediately
- `edit /tmp/file.txt` → still consent-based, not auto-blocked, because it is not blacklisted by default

### 3. Keep blacklist-first precedence intact and make it explicit in behavior
**Files:** `safety-guard/handlers.ts`, `REQUIREMENTS.md`

Planned changes:
- Ensure plan execution does not weaken the existing precedence rule where blacklist wins over whitelist.
- Document that the blacklist decision is now a strict block rather than a confirmation-gated block.
- Keep the rest of the priority model intact:
  1. `BLACKLIST` → strict block
  2. `WHITELIST` → allow
  3. default → consent required / block in non-interactive mode

### 4. Update requirements documentation to match task 11 behavior
**File:** `REQUIREMENTS.md`

Planned changes:
- Update section **3. Security Decision Model** so `BLACKLIST` no longer says:
  - interactive mode: requires explicit user confirmation
- Replace it with strict blocking semantics for all modes.
- Update section **10.4. Decision behavior for file I/O** so blacklist behavior is described as immediate block rather than confirmable.
- Update section **12.3. Non-interactive behavior** only as needed to keep wording accurate after blacklist becomes always-blocked.
- Update section **12.4. Logging behavior** so it reflects blocked blacklisted-path access rather than user rejection for that class of events.
- Update section **11.4. Prompt-policy mismatch currently present** only if task 11 materially reduces or removes the mismatch being described.
- Keep dangerous-command behavior documented as confirmable in interactive mode when no blacklisted path is involved.

### 5. Update test cases to reflect strict blacklist enforcement
**File:** `TEST-CASES.md`

Planned changes:
- Revise all blacklisted-path test expectations for `read`, `write`, `edit`, and `bash` so they expect immediate blocking rather than approve/reject behavior.
- Keep consent-based expectations unchanged for non-blacklisted paths.
- Keep dangerous-command interactive approval tests unchanged for commands such as `helm uninstall rel`.
- Update logging/notification expectations that currently depend on user rejection of blacklisted-path confirmations.

Specific test areas to update:
- section **4. Hardcoded Path Security Coverage**
- section **5. File I/O Protection - `read`**
- section **6. File I/O Protection - `write`**
- section **7. File I/O Protection - `edit`**
- section **8. Bash Path Extraction and Blacklisted Path Detection**
- section **10. Non-Interactive Logging and Sensitive Output Behavior**
- section **11. Notifications** where blacklist rejection wording is no longer valid
- section **12. Known Gap Verification** only if any statement becomes outdated after task 11

### 6. Keep notifications and prompts scoped to remaining consent-based flows
**Files:** `safety-guard/handlers.ts`, `TEST-CASES.md`, `REQUIREMENTS.md`

Planned changes:
- Ensure prompt/notification behavior remains only where user choice still exists:
  - dangerous bash commands
  - non-whitelisted, non-blacklisted file I/O paths
- Remove blacklisted-path confirmation expectations from docs/tests because there will no longer be a user decision branch for those cases.
- Avoid introducing new notification semantics unless strictly necessary for task 11.

### 7. Validate behavior after implementation
**Validation scope:** changed files and affected behavior only

Planned checks:
- Run the repository validation/lint command that applies to this project, if available.
- Verify blacklisted paths are blocked in both interactive and non-interactive contexts for:
  - `bash`
  - `read`
  - `write`
  - `edit`
- Verify non-blacklisted dangerous bash commands still require confirmation in interactive mode and remain blocked in non-interactive mode.
- Verify whitelisted and consent-required non-blacklisted file I/O behavior remains unchanged.

---

## File Change Summary
- `safety-guard/handlers.ts` — remove interactive override behavior for all blacklist matches while preserving dangerous-command approval flow for non-blacklisted commands
- `REQUIREMENTS.md` — align decision model, file I/O semantics, and logging/interaction wording with strict blacklist blocking
- `TEST-CASES.md` — update expectations from confirmable blacklist access to immediate blocking

## Acceptance Criteria
- Any monitored operation targeting a blacklisted path is blocked immediately, regardless of whether UI is available.
- This strict blocking applies consistently to:
  - blacklisted path access detected in `bash`
  - `read`
  - `write`
  - `edit`
- Dangerous bash commands that do **not** target blacklisted paths still follow the existing confirmation model in interactive mode and block in non-interactive mode.
- Whitelisted file I/O behavior remains auto-allow.
- Non-whitelisted, non-blacklisted file I/O behavior remains consent-based in interactive mode and blocked in non-interactive mode.
- `REQUIREMENTS.md` is updated so the documented decision model matches the planned runtime behavior.
- `TEST-CASES.md` is updated so blacklist-related test expectations no longer rely on interactive approval.
- The plan preserves blacklist-first precedence over whitelist decisions.

## Don't Do
- Do not change blacklist matching rules or path extraction scope for this task.
- Do not refactor unrelated dangerous-command regexes.
- Do not expand monitoring to unmonitored tools.
- Do not add new approval logic for blacklisted paths in any tool flow.
- Do not broaden this task into redirect/pipe parsing changes from task 12.
- Do not make unrelated logging redesign changes from task 10.
- Do not alter consent behavior for non-blacklisted file I/O beyond what is required to keep current semantics intact.
- Do not change dangerous bash approval semantics unless a blacklisted path is involved.

## Out of Scope
- auditing or adding monitoring for unmonitored/custom tools
- bash sanitization redesign
- redirect/pipe destination detection improvements
- broader logging enhancements beyond what is required to keep task 11 behavior accurately documented and testable
- unrelated prompt-policy refactors outside the direct effect of strict blacklist enforcement

## Notes / Risk
Main risk is changing only part of the blacklist decision flow and leaving inconsistent behavior between tools. The implementation should therefore update all monitored blacklist branches together and then align documentation/tests in the same task.