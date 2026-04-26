# Implementation Plan: Task 4 - Tilde Expansion for File I/O

This plan outlines the changes required to implement tilde expansion for `read`, `write`, and `edit` tool paths, closing a documented security gap where paths starting with `~` could bypass checks or fail to resolve correctly.

For this task, tilde expansion reuses the existing `expandTilde()` helper behavior. That means the implementation supports the same current semantics already used elsewhere in the extension and does **not** introduce full shell-style `~user` home-directory expansion.

## 1. Scope and Strategy
Although the TODO specifically mentions `read` and `write`, the `REQUIREMENTS.md` and `TEST-CASES.md` include `edit` in the same security context. To ensure consistency and follow the "Security First" and "Single Responsibility" principles, this implementation will cover all three file I/O tools.

### Key logic flow for File I/O:
1. Validate input (string check).
2. Detect path traversal (pre-resolution).
3. **Expand tilde (New Step).**
4. Resolve against CWD.
5. Apply Blacklist/Whitelist/Consent logic.

---

## 2. Proposed File Changes

### `safety-guard/utils.ts`
- No new functions required as `expandTilde` already exists.
- Ensure `expandTilde` is exported (already is).

### `safety-guard/handlers.ts`
- **Modify `handleFileIOTools`**:
    - Locate the path resolution logic: `const resolvedPath = resolve(effectiveCwd, pathParam);`.
    - Before resolution, apply `expandTilde(pathParam)` to a local variable.
    - Update `resolve` to use the tilde-expanded path.
    - Ensure the `securityLevel` check and logging use the correctly expanded/resolved path.
    - Maintain the use of the original `pathParam` in user-facing `ctx.ui.confirm` prompts to preserve user context.

### `REQUIREMENTS.md`
- **Update Section 6.3 (User-defined allowed paths)**:
    - Remove the "Important distinction" note that claims tilde expansion is not implemented for `read`/`write`/`edit`.
- **Update Section 10.3 (Resolution behavior)**:
    - Change description to state that `read`/`write`/`edit` inputs **are** tilde-expanded before resolution.
- **Update Section 14 (Known Gaps)**:
    - Remove the bullet point regarding missing tilde expansion for file I/O.

### `TEST-CASES.md`
- **Update TC-GAP-02**:
    - Rename/Repurpose from "File I/O Tilde Paths Are Not Expanded" to "File I/O Tilde Paths Are Correctly Expanded and Protected".
    - Update the "Expected" outcome to reflect that `~/.ssh/config` is now correctly detected as blacklisted.

### `TODO.md`
- Mark Task 4 as completed (after implementation).

---

## 3. Validation and Quality Assurance

### Manual Verification (Interactive)
1. Call `read { path: "~/.ssh/config" }` -> Verify it triggers a BLACKLIST confirmation.
2. Call `write { path: "~/test_safety_guard.txt" }` -> Verify it resolves to home directory and asks for CONSENT (or ALLOW if in whitelist).
3. Call `edit { path: "~/.env" }` -> Verify it triggers a BLACKLIST confirmation.

### Manual Verification (Non-Interactive)
1. With `ctx.hasUI = false`, call `read { path: "~/.ssh/config" }` -> Verify it is blocked.
2. With `ctx.hasUI = false`, call `write { path: "~/.aws/credentials" }` -> Verify it is blocked.
3. With `ctx.hasUI = false`, call `edit { path: "~/.env" }` -> Verify it is blocked.

### Regression Testing
1. Verify `read { path: "../etc/passwd" }` is still blocked by traversal check (Step 2 in logic flow).
2. Verify bare relative paths (e.g., `src/index.ts`) still resolve correctly against CWD.

### Linting & Formatting
- Run project-specific linting (if available) or verify syntax manually to ensure no regressions in `handlers.ts`.

---

## 4. Risks and Mitigations
- **Risk**: Overwriting `pathParam` might make user prompts confusing.
- **Mitigation**: Use a separate variable for the expanded path used in logic, while keeping the original string for UI display.
- **Risk**: `edit` tool might have different input structure.
- **Mitigation**: The current `handleFileIOTools` already abstracts this; ensure the type cast `(input as { path?: unknown }).path` remains safe.

---

## 5. Don't Do
- Do **not** refactor unrelated security logic in `handleFileIOTools` beyond the tilde-expansion change.
- Do **not** change the blacklist/whitelist/consent decision model as part of this task.
- Do **not** modify bash path extraction behavior in this task; bash tilde handling already exists and is out of scope here.
- Do **not** change traversal detection semantics unless a blocking issue is discovered.
- Do **not** alter user prompt wording beyond what is necessary to preserve current UX clarity.
- Do **not** broaden the task into support for bare filename detection, redirect parsing, or other TODO items.
- Do **not** update requirements or test cases in a way that changes intended security behavior beyond closing the tilde-expansion gap.
- Do **not** silently fix unrelated issues discovered during implementation; raise them separately unless they block Task 4.

---

## 6. Acceptance Criteria
- A file I/O path beginning with `~` is expanded to the user's home directory before path resolution and security checks.
- `read { path: "~/.ssh/config" }` is treated as access to a blacklisted path and follows existing blacklist behavior.
- `write { path: "~/.aws/credentials" }` is treated as access to a blacklisted path and follows existing blacklist behavior.
- `edit { path: "~/.env" }` is treated as access to a blacklisted path and follows existing blacklist behavior.
- Non-tilde relative paths such as `src/index.ts` continue to resolve against the effective current working directory exactly as before.
- Path traversal inputs such as `../secret.txt` continue to be blocked with existing traversal behavior.
- `REQUIREMENTS.md` no longer documents missing tilde expansion for file I/O paths.
- `TEST-CASES.md` no longer treats file I/O tilde expansion as a known gap and instead validates the corrected behavior.
- `TODO.md` task 4 is marked as completed after implementation is finished.
