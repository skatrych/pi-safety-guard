# Implementation Plan for TODO #1: Add Monitoring for `edit` Tool Calls

## Goal
Extend the Safety Guard extension so that `edit` tool calls are protected by the same path-based security model already used for `read` and `write`.

This change should close the current enforcement gap described in `REQUIREMENTS.md` section 2.2 and section 14, without refactoring unrelated behavior.

## Important scope boundary
This plan addresses **only TODO #1**.

It should **not** implement or change the following while working on this task:
- TODO #3: blacklist accumulation across sessions
- TODO #4: tilde expansion for `read` / `write`
- TODO #5: bash bare filename detection
- TODO #11: strict hard-blocking of blacklisted paths in interactive mode

That means the new `edit` handling should intentionally match the **current** `read` / `write` behavior, even if some of that behavior is planned to change later.

---

## Current behavior summary from requirements and code

### What is already protected
The current extension monitors only:
- `bash`
- `read`
- `write`

Relevant implementation is in:
- `safety-guard/handlers.ts`
- `safety-guard/security.ts`
- `safety-guard/index.ts`

### How file I/O is currently handled
`handleFileIOTools()` in `safety-guard/handlers.ts` currently does this for `read` and `write`:
1. return early if `input.path` is missing
2. detect path traversal using `hasPathTraversal()`
3. resolve the path against `ctx.cwd || process.cwd()`
4. evaluate resolved path through `checkPathSecurity()`
5. apply current decision model:
   - `BLOCK`: ask user for confirmation in interactive mode, block in non-interactive mode
   - `ALLOW`: allow automatically
   - `CONSENT_REQUIRED`: ask user in interactive mode, block in non-interactive mode

### Current gap
`edit` is not included in `handleToolCall()` routing, so it bypasses all path checks.

---

## Expected end result
After implementation:
- `edit` tool calls with a `path` field are monitored
- `edit` path handling behaves consistently with `read` and `write`
- path traversal attempts through `edit` are blocked
- blacklisted paths used by `edit` go through the same current decision flow as `read` / `write`
- whitelisted paths used by `edit` are auto-allowed
- non-whitelisted/non-blacklisted paths require user consent in interactive mode and are blocked in non-interactive mode
- `edit` calls without a usable string `path` continue as graceful no-op from the extension perspective, matching current `read` / `write` behavior
- `edit` inherits the current `read` / `write` path-resolution limitation: tool input paths are resolved against cwd without tilde expansion

---

## Specific file changes

### 1. `safety-guard/handlers.ts`
This will be the main file to change.

#### A. Expand file I/O handler scope to include `edit`
Update the file I/O handling logic so `edit` is treated as a monitored file-path tool alongside `read` and `write`.

Recommended approach:
- keep a single shared path-based handler for file tools
- allow that handler to accept `toolName` values `read`, `write`, and `edit`

Why:
- avoids duplicating security logic
- keeps behavior aligned across all file-mutating tools
- minimizes risk of future drift between `write` and `edit`

#### B. Broaden the input type handled by the file I/O handler
Today the handler expects only:
- `{ path?: string }`

`edit` input also includes an `edits` array, but for TODO #1 the security decision depends only on `path`.

Planned change:
- update the handler typing so it can accept `edit` payloads without requiring separate logic for `edits`
- keep validation lightweight: only `path` matters for this task
- add minimal runtime guards so the shared handler only continues when `input` is object-like and `path` is a string

Important:
- do not add deep validation for `edits[]` content unless required to satisfy TypeScript
- do not introduce content-based scanning of `oldText` / `newText`; that is outside this TODO
- do not assume TypeScript typing alone is sufficient; runtime input must not be passed to `resolve()` unless `path` is confirmed to be a string

#### C. Route `edit` in `handleToolCall()`
Update the dispatcher so that:
- `bash` still goes to `handleBashTools()`
- `read`, `write`, and `edit` go to the shared file-path handler

This is the actual enforcement activation point for TODO #1.

#### D. Logging updates
Ensure logs remain clear and tool-specific.

Wherever the shared file handler logs actions, verify the output is meaningful for `edit`, for example:
- blocked `edit` on blacklisted path
- allowed `edit` on whitelisted path
- user rejected consent for `edit`

This likely already works because logs interpolate `toolName`, but it should be explicitly verified.

Mandatory safety requirement:
- do not log `event.input`
- do not stringify the full `edit` payload for debugging
- do not log `edits[]`, `oldText`, or `newText`
- do not include edit replacement content in confirmation dialogs

Only path and decision metadata should appear in logs or prompts.

---

### 2. `REQUIREMENTS.md`
This file should be updated after implementation so the documented behavior matches the code.

Required documentation updates:
- Section 2.1 Monitored tools: add `edit`
- Section 2.2 Unmonitored tools: remove `edit`
- Section 10 title and wording: update from `read`/`write` only to include `edit`
- Section 10.4 decision behavior: state that the same path-based behavior applies to `read`, `write`, and `edit`
- Section 10.5 missing input behavior: include `edit`
- Section 13 Graceful No-Op Cases: include monitored `edit` with missing `path`
- Section 14 Known Gaps / Current Limitations: remove or mark resolved the statement that `edit` is not protected

Note:
Do this only if code implementation is completed in the same change. Requirements should not claim support that does not yet exist.

---

### 3. `TEST-CASES.md`
This file should be updated with test coverage for the new behavior.

Add test cases covering:
- `edit` on a file inside the project directory whitelist
- `edit` on a blacklisted path
- `edit` on project-root `.env`
- `edit` on nested project `.env` / `.env.*`
- explicit verification that blacklist takes precedence over the project-directory whitelist
- `edit` using path traversal
- `edit` on a path outside whitelist in interactive mode
- `edit` on a path outside whitelist in non-interactive mode
- `edit` call without `path`
- `edit` call with non-string `path`

If the repository already has automated tests for extension behavior, add executable regression coverage there in addition to `TEST-CASES.md`.
If there is no automated test harness for this area, document the scenarios in `TEST-CASES.md` and make that limitation explicit in the PR notes.

If `TEST-CASES.md` already has sections for `read` / `write`, mirror that structure instead of inventing a new format.

---

## Detailed implementation steps

### Phase 1: Understand current file I/O flow
Before editing code:
1. Re-read `handleFileIOTools()` in `safety-guard/handlers.ts`
2. Confirm exactly how `ToolCallEvent.input` is typed by the Pi SDK, if needed
3. Verify whether TypeScript changes are needed to avoid unsafe casts when `edit` payloads are passed in
4. Check whether the repository already has automated tests covering handlers or extension events, so this regression can be captured in executable tests if infrastructure exists

Expected outcome:
- clear understanding of the minimal change needed to reuse the existing handler
- clear decision whether automated regression coverage can be added in this change

### Phase 2: Extend dispatcher coverage
1. Modify `handleToolCall()` in `safety-guard/handlers.ts`
2. Add `edit` to the branch that routes path-based tools into the shared file handler
3. Keep the `configLoaded` gate unchanged

Expected outcome:
- `edit` no longer bypasses monitoring

### Phase 3: Make shared file handler compatible with `edit`
1. Adjust handler input typing so `edit` payloads are accepted cleanly
2. Keep `path` as the only required field for security decisions
3. Preserve early return when `path` is absent

Expected outcome:
- `edit` benefits from the same flow without unnecessary special cases

### Phase 4: Verify current-behavior parity with `read` / `write`
Validate that `edit` now follows the same steps:
1. path traversal check
2. path resolution against effective cwd
3. blacklist-first decision via `checkPathSecurity()`
4. interactive confirmation or blocking based on current rules

Expected outcome:
- `edit` behavior is consistent, predictable, and low-risk

### Phase 5: Update docs and tests
After code behavior is confirmed:
1. update `REQUIREMENTS.md`
2. update `TEST-CASES.md`
3. optionally update `TODO.md` only after implementation is complete and verified

Expected outcome:
- repository documentation reflects actual extension behavior

---

## Decision details the implementer must preserve

### Preserve current blacklist behavior
Even though TODO #11 plans to make blacklisted paths strictly blocked, this task must preserve the **current** behavior:
- interactive mode: confirmation dialog for blacklisted file paths
- non-interactive mode: blocked

Reason:
- TODO #1 is about tool coverage, not a policy change
- mixing those changes would make review harder and create scope creep

### Preserve current path resolution behavior
Do not add tilde expansion to `edit` unless it is already explicitly used by the shared file handler design.

Reason:
- TODO #4 exists specifically for tilde expansion behavior
- implementing it here would mix concerns and make requirements tracking less clear

### Preserve graceful no-op behavior
If an `edit` event arrives without a usable string `path`, return without intervention.

Reason:
- this matches existing monitored-tool conventions in the code and requirements
- this task is about adding `edit` to current file-tool enforcement, not redesigning malformed-input handling

Important note:
- this is an intentional parity choice for TODO #1, not an ideal long-term security posture
- if malformed monitored-tool payloads should become hard failures later, that should be tracked as a separate change

### Preserve shared decision engine
Do not create a separate security policy for `edit`.

Reason:
- `checkPathSecurity()` already defines the intended blacklist/whitelist/consent model
- a separate path policy for `edit` would increase maintenance cost and inconsistency risk

---

## Suggested validation checklist
The less senior engineer should manually verify the following scenarios after implementation.

### Positive / allowed scenarios
1. `edit` a file under the current project directory
   - expected: auto-allowed because project directory is whitelisted
2. `edit` a file under another configured allowed path
   - expected: auto-allowed

### Blocking / consent scenarios
3. `edit` a blacklisted path in interactive mode
   - expected: same confirmation flow currently used for `read` / `write`
4. `edit` a blacklisted path in non-interactive mode
   - expected: blocked immediately
5. `edit` a non-whitelisted, non-blacklisted path in interactive mode
   - expected: consent dialog
6. `edit` a non-whitelisted, non-blacklisted path in non-interactive mode
   - expected: blocked

### Security edge cases
7. `edit` with `../` traversal path
   - expected: blocked as path traversal
8. `edit` with benign path names containing `..` internally, such as `my..file`
   - expected: not treated as traversal based only on that filename pattern
9. `edit` on `./.env`
   - expected: blacklist behavior applies even though project directory is whitelisted
10. `edit` on `subdir/.env` or `subdir/.env.local`
   - expected: blacklist behavior applies even though path is under the project directory
11. `edit` call without `path`
   - expected: extension does nothing
12. `edit` call with non-string `path`
   - expected: extension does nothing and does not throw

### Logging checks
13. Verify logs mention `edit` correctly in allow/block/reject cases
14. Verify no full sensitive content from `edits[]` is logged
15. Verify prompts shown to the user do not include `oldText` / `newText`

That last point is important: logs and prompts should reference the path and decision, not the textual replacement content.

---

## Don't Do

- Do not implement anything beyond TODO #1.
- Do not fix or partially address TODO #3, TODO #4, TODO #5, or TODO #11 in this task.
- Do not refactor unrelated behavior or redesign the security model.
- Do not create a separate security policy for `edit`; it must reuse the current shared path-based decision model.
- Do not introduce a separate `handleEditTools()` path unless a clear technical limitation makes reuse impossible.
- Do not change current `read` / `write` semantics beyond adding `edit` coverage.
- Do not add tilde expansion for `edit`; it must inherit the current `read` / `write` resolution behavior.
- Do not add deep validation of `edits[]`.
- Do not add content scanning of `oldText` / `newText`.
- Do not rely on TypeScript typing alone for safety; do not pass unchecked runtime input to `resolve()`.
- Do not treat malformed `edit` payload handling as part of a broader policy redesign in this task.
- Do not log `event.input`, full `edit` payloads, `edits[]`, `oldText`, or `newText`.
- Do not include edit replacement content in user confirmation dialogs.
- Do not update `REQUIREMENTS.md` before the implementation is complete and verified.
- Do not skip validation of blacklist precedence for project `.env` paths under the whitelisted project directory.

## Risks and review points

### Risk 1: Accidental scope expansion
A less senior engineer may try to also “fix” related TODOs while touching the same code.

Review guidance:
- reject unrelated policy changes in this PR
- keep implementation limited to adding `edit` coverage

### Risk 2: Over-validating the `edit` payload
It may be tempting to add validation for `edits[]`, `oldText`, or `newText`.

Review guidance:
- only add the minimum type handling necessary for safe compilation
- payload content validation is not required for this TODO

### Risk 3: Creating duplicate handlers
A separate `handleEditTools()` function may be introduced.

Review guidance:
- prefer reusing `handleFileIOTools()` unless a clear technical limitation forces a split
- if a split is proposed, require strong justification because behavior must remain aligned

### Risk 4: Logging sensitive text replacements
Because `edit` contains content changes, careless logging could expose file content.

Review guidance:
- log path and decision only
- do not log `oldText`, `newText`, `edits[]`, or full edit payloads
- do not show edit replacement content in confirmation dialogs

---

## Proposed implementation sequence for the engineer
1. Update `safety-guard/handlers.ts` dispatcher to route `edit`
2. Adjust shared file handler typing to accept `edit` payloads safely
3. Verify `edit` inherits traversal + path security behavior unchanged
4. Validate logs and prompts remain path-based and do not include edit content
5. Add automated regression tests if the repository already supports them; otherwise update `TEST-CASES.md`
6. Ensure test coverage includes project `.env` precedence over project-directory whitelist
7. Update `REQUIREMENTS.md`
8. Run the project lint/type validation focused on changed code

---

## Definition of done
TODO #1 can be considered complete when all of the following are true:
- `edit` no longer bypasses security monitoring
- `edit` uses the same path-based enforcement flow as `read` / `write`
- no unrelated TODO behavior was changed
- docs and test cases were updated to reflect the new support
- logs and prompts do not expose edit content
- project `.env` blacklist precedence over project-directory whitelist is validated
- automated regression coverage is added if an existing test harness is available; otherwise `TEST-CASES.md` is updated and the limitation is documented
- changed code passes lint/type validation

---

## Short reviewer summary
This task is a targeted security coverage improvement.

The cleanest implementation is to:
- reuse the existing file I/O path-security handler
- route `edit` through it
- avoid content-based logic for `edits[]`
- preserve current behavior exactly, except that `edit` is no longer unmonitored
