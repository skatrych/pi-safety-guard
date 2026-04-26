# Implementation Plan for Task 5

## Task
Improve bash path extraction to detect bare filenames, based on `TODO.md` task 5, while keeping `REQUIREMENTS.md` and `TEST-CASES.md` consistent.

## Goal
Close the current security gap where bash commands referencing sensitive files via bare filenames (for example `cat .env` or `cat config.json`) are ignored by the bash path extractor because they do not start with `~`, `/`, `./`, or `../`.

## Planned Changes

### 1. Update bash path extraction logic
**File:** `safety-guard/security.ts`

Planned changes:
- Extend `extractPathsFromCommand()` so that it can treat eligible bare filename/path tokens as filesystem candidates.
- Resolve detected bare tokens against the effective `cwd`, the same way explicit relative paths are resolved.
- Keep the current existing handling for:
  - tilde paths
  - absolute paths
  - explicit relative paths
  - quote stripping
  - option skipping
  - command-name token skipping
  - trailing redirect/operator stripping
- Introduce conservative rules for bare-token detection to reduce false positives. The detection should only consider tokens that look like probable local file references rather than arbitrary shell words.

Suggested acceptance-oriented behavior to implement:
- Detect likely file/path tokens such as:
  - `.env`
  - `.env.local`
  - `config.json`
  - `secrets.txt`
  - `dir/file.txt`
- Continue ignoring obvious non-path shell syntax and control words where possible.

### 2. Keep false positives under control
**File:** `safety-guard/security.ts`

Planned changes:
- Add a small helper or inline predicate that defines when a bare token is path-like enough to be treated as a candidate.
- Make the heuristic intentionally conservative so that common command arguments are not broadly misclassified as paths.
- Ensure shell operators, flags, and skipped command tokens still do not become path candidates.
- Ensure tokens already handled by existing explicit-path rules are not double-processed.

### 3. Preserve blacklist-first enforcement behavior
**File:** `safety-guard/security.ts`

Planned changes:
- Keep `findBlacklistedPathInCommand()` behavior unchanged at the decision level: it should still return the first offending extracted path.
- Do not change the approval/blocking flow in `safety-guard/handlers.ts` for this task.
- Only the extraction coverage should expand.

### 4. Align requirements documentation with the new behavior
**File:** `REQUIREMENTS.md`

Planned changes:
- Update section **9. Bash Path Extraction Rules** so it no longer states that bare words are intentionally ignored.
- Replace that description with the new expected runtime behavior:
  - explicit path forms are still extracted
  - path-like bare filenames and relative subpaths are also extracted and resolved against `cwd`
  - detection remains heuristic/conservative to reduce false positives
- Update section **14. Known Gaps / Current Limitations** to remove or revise the statement that bash path extraction ignores bare filenames.

### 5. Update test cases to reflect the new expected behavior
**File:** `TEST-CASES.md`

Planned changes:
- Replace the current gap-verification expectation that bare filenames are ignored.
- Update bash path extraction coverage with positive cases for bare filename detection, especially for sensitive project files.

Specific test-case updates to make:
- Revise **TC-BASH-PATH-09** so it expects a bare filename/path token to be treated as a path candidate instead of ignored.
- Add or adjust cases covering:
  - `cat .env` resolving to `<cwd>/.env` and being treated as blacklisted
  - `cat .env.local` resolving to `<cwd>/.env.local` and being treated as blacklisted
  - `cat dir/.env` resolving relative to `cwd` and being treated as blacklisted when applicable
  - a benign non-path token scenario to verify the heuristic stays conservative
- Update **Known Gap Verification** section to remove the statement that bare filenames are not detected, if that statement still exists after test edits.

### 6. Validate changed behavior
**Validation scope:** changed code only

Planned checks:
- Run repository lint/check command(s) applicable to the project after implementation.
- Verify that bash path extraction still catches previously supported forms:
  - `~/.ssh/id_rsa`
  - `/etc/passwd`
  - `./.env`
- Verify that newly supported bare forms are caught:
  - `.env`
  - `.env.local`
  - `subdir/.env`
- Verify that obviously non-path arguments are not over-detected.

## File Change Summary
- `safety-guard/security.ts` — extend bash path extraction for bare path-like tokens
- `REQUIREMENTS.md` — align documented behavior with new extraction rules
- `TEST-CASES.md` — update/add test cases for bare filename detection

## Acceptance Criteria
- Bash path extraction detects eligible bare file/path tokens used in `bash` commands and resolves them against the effective `cwd`.
- Sensitive project files referenced as bare tokens are caught by blacklist checks, including at minimum:
  - `.env`
  - `.env.local`
  - nested relative forms such as `dir/.env`
- Previously supported extracted path forms continue to work unchanged:
  - `~/...`
  - `/...`
  - `./...`
  - `../...`
- The decision flow for dangerous commands and file I/O tools remains unchanged.
- `REQUIREMENTS.md` no longer documents bare filenames as intentionally ignored.
- `TEST-CASES.md` includes positive coverage for bare filename detection and no longer asserts that such tokens are ignored.
- Repository lint/checks relevant to the changed code pass.

## Don't Do
- Do not treat every non-option bash token as a filesystem path candidate.
- Do not refactor unrelated bash sanitization or dangerous-command pattern logic.
- Do not change interactive approval semantics for blacklisted paths or dangerous commands as part of task 5.
- Do not expand scope to unmonitored tools.
- Do not add redirect/pipe destination handling unless it is strictly necessary for bare filename detection in this task.

## Out of Scope
To keep this task narrowly aligned with task 5, the plan does **not** include:
- changing interactive override behavior for blacklisted paths
- refactoring dangerous command detection
- adding support for redirect/pipe destination parsing beyond current extraction scope
- expanding monitoring to unmonitored tools

## Notes / Risk
Main implementation risk is false positives in bash parsing. The solution should therefore prefer a conservative bare-token heuristic rather than treating every non-option token as a path.