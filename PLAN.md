# Plan for Task 3: Fix project-specific blacklist accumulation across sessions

## Goal
Ensure project-specific blacklist entries added during `session_start` are reset per session, so `.env` blacklist rules do not accumulate across multiple sessions in the same process. Only the current session's project-specific `.env` rules should remain active; project-specific rules from previous sessions must be removed.

## Planned file changes

### 1. `safety-guard/handlers.ts`
- Update `onSessionStart` so session-derived blacklist rules are rebuilt cleanly on every session start.
- Keep the static global blacklist entries intact.
- Avoid appending new project-specific `.env` regexes onto previously added session-specific entries.
- Apply the same reset/rebuild behavior in both the normal path and the fallback error path.
- Verify whether the blacklist array is referenced elsewhere (e.g., passed to other modules or closures). If so, use mutate-in-place (`splice`/`length = 0` + `push`) rather than reassignment to ensure all references stay in sync.

### 2. `safety-guard/constants.ts` or `safety-guard/state.ts` (only if needed)
- If the cleanest implementation requires it, separate static blacklist definitions from session-specific blacklist entries.
- Prefer a minimal change that makes ownership of static vs dynamic blacklist rules explicit.

### 3. `TEST-CASES.md`
- Add or update a test case covering repeated `session_start` calls with different working directories.
- Verify that only the current session's project `.env` paths are blacklisted, while permanent blacklist entries remain unchanged.

## Validation
- Run the project lint/check command if available.
- Manually verify that starting multiple sessions in one process does not grow the blacklist indefinitely.
- Confirm that blacklist protection for built-in sensitive paths still works after the change.
