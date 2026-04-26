# Safety Guard Extension - Test Cases

## 1. Lifecycle and Tool Dispatch

### TC-LIFE-01: Pre-Initialization Block
- **Context:** Extension instance exists, but `session_start` has not completed.
- **Action:** Trigger `tool_call` for `read` with `{ path: "file.txt" }`.
- **Expected:** Tool call is blocked with reason `"Configuration not fully loaded"`.

### TC-LIFE-02: Unmonitored Tool Pass-Through
- **Context:** A tool outside extension scope is called.
- **Action:** Trigger `tool_call` for `list_files`.
- **Expected:** Extension returns `undefined`; tool is not intercepted.

### TC-LIFE-03: Missing Bash Command Input
- **Context:** `bash` tool call lacks `command`.
- **Action:** Trigger `tool_call` for `bash` with `{}`.
- **Expected:** Extension returns `undefined`.

### TC-LIFE-04: Missing Read Path Input
- **Context:** `read` tool call lacks `path`.
- **Action:** Trigger `tool_call` for `read` with `{}`.
- **Expected:** Extension returns `undefined`.

### TC-LIFE-05: Missing Write Path Input
- **Context:** `write` tool call lacks `path`.
- **Action:** Trigger `tool_call` for `write` with `{}`.
- **Expected:** Extension returns `undefined`.

---

## 2. Session Initialization and Prompt Augmentation

### TC-INIT-01: Append to `systemPrompt` Only
- **Context:** `ctx.systemPrompt` exists, `ctx.aiSystemMessage` is absent.
- **Action:** Run `session_start`.
- **Expected:** Original `systemPrompt` content is preserved and security policy is appended.

### TC-INIT-02: Append to `aiSystemMessage` Only
- **Context:** `ctx.aiSystemMessage` exists, `ctx.systemPrompt` is absent.
- **Action:** Run `session_start`.
- **Expected:** Original `aiSystemMessage` content is preserved and security policy is appended.

### TC-INIT-03: Append to Both Prompt Fields
- **Context:** Both prompt fields exist.
- **Action:** Run `session_start`.
- **Expected:** Policy is appended to both, without replacing original content.

### TC-INIT-04: No Prompt Fields Present
- **Context:** Neither prompt field exists.
- **Action:** Run `session_start`.
- **Expected:** No prompt mutation attempted; initialization completes normally.

### TC-INIT-05: Project Directory Added to Whitelist
- **Context:** Session starts with cwd `/prj/app`.
- **Action:** Run `session_start`.
- **Expected:** `/prj/app` becomes part of runtime whitelist.

### TC-INIT-06: Project `.env` Blacklist Added
- **Context:** Session starts with cwd `/prj/app`.
- **Action:** Run `session_start`.
- **Expected:** Runtime blacklist gains patterns covering `/prj/app/.env`, `/prj/app/.env.*`, and nested equivalents.

### TC-INIT-07: Repeated Session Accumulation Behavior
- **Context:** Same extension instance handles multiple `session_start` events in one process.
- **Action:** Run `session_start` twice for same cwd.
- **Expected:** Additional project `.env` blacklist regexes are appended again; current implementation accumulates entries rather than resetting them.

---

## 3. Configuration Loading, Validation, and Fallback

### TC-CONF-01: Precedence - Project Local Wins
- **Context:** Config exists in both `<CWD>/.pi/settings.json` and `<ParentDir>/pi/agent/settings.json`.
- **Action:** Run `session_start`.
- **Expected:** Project-local config is used.

### TC-CONF-02: Precedence - Parent Agent Used When Local Missing
- **Context:** Local config missing; parent agent config exists.
- **Action:** Run `session_start`.
- **Expected:** `<ParentDir>/pi/agent/settings.json` is used.

### TC-CONF-03: Precedence - Parent Pi Used When Higher Sources Missing
- **Context:** Local and parent agent configs missing; `<ParentDir>/pi/settings.json` exists.
- **Action:** Run `session_start`.
- **Expected:** Parent Pi config is used.

### TC-CONF-04: No Config Found
- **Context:** None of the three config files exists.
- **Action:** Run `session_start`.
- **Expected:** Defaults are used; base whitelist and cwd still become active.

### TC-CONF-05: Invalid Config Root Type - Non-Object
- **Context:** Config file content parses to a primitive value such as a string or number.
- **Action:** Run `session_start`.
- **Expected:** Validation fails and invalid values are not applied.

### TC-CONF-06: Invalid Config Root Type - Null
- **Context:** Config file content parses to `null`.
- **Action:** Run `session_start`.
- **Expected:** Validation fails and invalid values are not applied.

### TC-CONF-07: Invalid Config Root Type - Array
- **Context:** Config file content parses to an array.
- **Action:** Run `session_start`.
- **Expected:** Validation fails and invalid values are not applied.

### TC-CONF-08: Invalid `extensions.allowedPaths` Type
- **Context:** `extensions.allowedPaths` is a string or number.
- **Action:** Run `session_start`.
- **Expected:** Validation fails and invalid value is ignored.

### TC-CONF-09: Invalid `extensions.allowedPaths` Elements
- **Context:** `extensions.allowedPaths` contains non-string elements.
- **Action:** Run `session_start`.
- **Expected:** Validation fails and invalid value is ignored.

### TC-CONF-10: Invalid `extensions.notificationsEnabled` Type
- **Context:** `extensions.notificationsEnabled` is not boolean.
- **Action:** Run `session_start`.
- **Expected:** Validation fails and invalid value is ignored.

### TC-CONF-11: Malformed JSON Fallback
- **Context:** Config file exists but contains malformed JSON.
- **Action:** Run `session_start`.
- **Expected:** Load fails, fallback whitelist is applied, notifications become `true`, project `.env` blacklist is still added, and extension does not remain permanently blocked.

### TC-CONF-12: Tilde Expansion in Allowed Paths
- **Context:** Config contains `"extensions.allowedPaths": ["~/Downloads/safe"]`.
- **Action:** Run `session_start`, then `read ~/Downloads/safe/file.txt`.
- **Expected:** Path is treated as allowed after tilde expansion.

### TC-CONF-13: Whitelist Merge and Deduplication
- **Context:** Config contains duplicate or base-equivalent allowed paths such as `~/.pi/`.
- **Action:** Run `session_start`.
- **Expected:** Runtime whitelist is rebuilt from merged unique path strings.

---

## 4. Hardcoded Path Security Coverage

### TC-PATH-01: Home-Level Secret Files and Directories
- **Context:** Interactive session.
- **Action:** Trigger `read` for each representative absolute home-based path:
  - `<HOME>/.pi/agent/auth.json`
  - `<HOME>/.ssh/id_rsa`
  - `<HOME>/.gnupg/pubring.kbx`
  - `<HOME>/Library/Keychains/login.keychain-db`
  - `<HOME>/.aws/credentials`
  - `<HOME>/Pictures/Photos Library.photoslibrary/database`
  - `<HOME>/.env`
  - `<HOME>/.env.local`
  - `<HOME>/.gitconfig`
- **Expected:** Each path is treated as blacklisted and requires confirmation in interactive mode.

### TC-PATH-02: System Paths
- **Context:** Interactive session.
- **Action:** Trigger `read` for representative paths under `/etc/`, `/usr/`, and `/System/`.
- **Expected:** Each path is treated as blacklisted and requires confirmation.

### TC-PATH-03: Base Whitelist Paths
- **Context:** Session initialized.
- **Action:** Trigger `read` under:
  - `<HOME>/.pi/`
  - `/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/`
- **Expected:** Access is allowed automatically unless a more specific blacklist rule applies.

### TC-PATH-04: Blacklist Overrides Whitelist for File I/O
- **Context:** User has configured `~/.ssh` inside `extensions.allowedPaths`.
- **Action:** Trigger `read <HOME>/.ssh/config`.
- **Expected:** Blacklist still wins; confirmation is required.

---

## 5. File I/O Protection - `read`

### TC-READ-01: Whitelisted Read Allowed
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `read { path: "src/index.ts" }`.
- **Expected:** Resolved path is inside project whitelist; access is allowed automatically.

### TC-READ-02: Blacklisted Read Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `read { path: "<HOME>/.ssh/config" }`.
- **Expected:** Confirmation prompt shown; rejection blocks, approval allows.

### TC-READ-03: Consent-Required Read Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `read { path: "/tmp/report.txt" }`.
- **Expected:** Consent prompt shown; rejection blocks, approval allows.

### TC-READ-04: Blacklisted Read Non-Interactive
- **Context:** `ctx.hasUI = false`.
- **Action:** Trigger `read { path: "<HOME>/.ssh/config" }`.
- **Expected:** Operation is blocked.

### TC-READ-05: Consent-Required Read Non-Interactive
- **Context:** `ctx.hasUI = false`.
- **Action:** Trigger `read { path: "/tmp/report.txt" }`.
- **Expected:** Operation is blocked.

### TC-READ-06: Whitelisted Read Non-Interactive
- **Context:** `ctx.hasUI = false`, cwd initialized and whitelisted.
- **Action:** Trigger `read { path: "src/index.ts" }`.
- **Expected:** Operation is allowed automatically.

### TC-READ-07: Traversal Block
- **Context:** Attempt to escape current directory constraints.
- **Action:** Trigger `read { path: "../../../etc/passwd" }`.
- **Expected:** Blocked with reason `"Path traversal detected"`.

### TC-READ-08: Traversal False Positive Avoidance
- **Context:** Filename contains `..` but is not traversal.
- **Action:** Trigger `read` for each:
  - `/prj/app/..config/file.txt`
  - `/prj/app/my..file`
- **Expected:** Not blocked by traversal detection alone; proceeds to normal whitelist/blacklist/consent logic.

### TC-READ-09: Home `.env` Variant Protection
- **Context:** Interactive session.
- **Action:** Trigger `read { path: "<HOME>/.env.local" }`.
- **Expected:** Blacklisted; confirmation required.

### TC-READ-10: Project `.env` Variant Protection Matrix
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `read` for:
  - `.env`
  - `.env.local`
  - `packages/api/.env`
  - `apps/web/.env.production`
- **Expected:** Each path is treated as blacklisted by project-specific runtime rules.

---

## 6. File I/O Protection - `write`

### TC-WRITE-01: Whitelisted Write Allowed
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `write { path: "out/report.txt" }`.
- **Expected:** Allowed automatically.

### TC-WRITE-02: Blacklisted Write Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `write { path: "<HOME>/.ssh/config" }`.
- **Expected:** Confirmation prompt shown; rejection blocks, approval allows.

### TC-WRITE-03: Consent-Required Write Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `write { path: "/tmp/output.txt" }`.
- **Expected:** Consent prompt shown; rejection blocks, approval allows.

### TC-WRITE-04: Blacklisted Write Non-Interactive
- **Context:** `ctx.hasUI = false`.
- **Action:** Trigger `write { path: "<HOME>/.aws/credentials" }`.
- **Expected:** Operation is blocked.

### TC-WRITE-05: Consent-Required Write Non-Interactive
- **Context:** `ctx.hasUI = false`.
- **Action:** Trigger `write { path: "/tmp/output.txt" }`.
- **Expected:** Operation is blocked.

### TC-WRITE-06: Whitelisted Write Non-Interactive
- **Context:** `ctx.hasUI = false`, cwd initialized and whitelisted.
- **Action:** Trigger `write { path: "out/report.txt" }`.
- **Expected:** Operation is allowed automatically.

### TC-WRITE-07: Write Traversal Block
- **Context:** Attempted traversal path.
- **Action:** Trigger `write { path: "../../secret.txt" }`.
- **Expected:** Blocked with reason `"Path traversal detected"`.

---

## 7. File I/O Protection - `edit`

### TC-EDIT-01: Whitelisted Edit Allowed
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `edit { path: "src/index.ts", edits: [...] }`.
- **Expected:** Resolved path is inside project whitelist; access is allowed automatically.

### TC-EDIT-02: Blacklisted Edit Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `edit { path: "<HOME>/.ssh/config", edits: [...] }`.
- **Expected:** Confirmation prompt shown; rejection blocks, approval allows.

### TC-EDIT-03: Consent-Required Edit Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `edit { path: "/tmp/report.txt", edits: [...] }`.
- **Expected:** Consent prompt shown; rejection blocks, approval allows.

### TC-EDIT-04: Blacklisted Edit Non-Interactive
- **Context:** `ctx.hasUI = false`.
- **Action:** Trigger `edit { path: "<HOME>/.ssh/config", edits: [...] }`.
- **Expected:** Operation is blocked.

### TC-EDIT-05: Consent-Required Edit Non-Interactive
- **Context:** `ctx.hasUI = false`.
- **Action:** Trigger `edit { path: "/tmp/report.txt", edits: [...] }`.
- **Expected:** Operation is blocked.

### TC-EDIT-06: Whitelisted Edit Non-Interactive
- **Context:** `ctx.hasUI = false`, cwd initialized and whitelisted.
- **Action:** Trigger `edit { path: "src/index.ts", edits: [...] }`.
- **Expected:** Operation is allowed automatically.

### TC-EDIT-07: Edit Traversal Block
- **Context:** Attempt to escape current directory constraints.
- **Action:** Trigger `edit { path: "../../../etc/passwd", edits: [...] }`.
- **Expected:** Blocked with reason `"Path traversal detected"`.

### TC-EDIT-08: Edit Home `.env` Variant Protection
- **Context:** Interactive session.
- **Action:** Trigger `edit { path: "<HOME>/.env.local", edits: [...] }`.
- **Expected:** Blacklisted; confirmation required.

### TC-EDIT-09: Edit Project `.env` Variant Protection Matrix
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `edit` for:
  - `.env`
  - `.env.local`
  - `packages/api/.env`
- **Expected:** Each path is treated as blacklisted by project-specific runtime rules.

### TC-EDIT-10: Missing Edit Path Input
- **Context:** `edit` tool call lacks `path`.
- **Action:** Trigger `tool_call` for `edit` with `{ edits: [...] }`.
- **Expected:** Extension returns `undefined`.

### TC-EDIT-11: Non-String Edit Path Input
- **Context:** `edit` tool call has a non-string `path`.
- **Action:** Trigger `tool_call` for `edit` with `{ path: 123, edits: [...] }`.
- **Expected:** Extension returns `undefined`.

### TC-EDIT-12: Edit Content Privacy
- **Context:** Any `edit` tool call.
- **Action:** Inspect logs and user prompts.
- **Expected:** Neither the logs nor the prompts contain the `edits`, `oldText`, or `newText` content. Only the path and decision are visible.

---

## 8. Bash Path Extraction and Blacklisted Path Detection

### TC-BASH-PATH-01: Tilde Path Detection
- **Context:** Interactive session.
- **Action:** Execute `bash` command `cat ~/.ssh/id_rsa`.
- **Expected:** Path is extracted and treated as blacklisted.

### TC-BASH-PATH-02: Absolute Path Detection
- **Context:** Interactive session.
- **Action:** Execute `bash` command `ls -la /etc/passwd`.
- **Expected:** Path is extracted and treated as blacklisted.

### TC-BASH-PATH-03: Explicit Relative Path Detection
- **Context:** Session initialized with cwd `/prj/app` and project `.env` blacklist active.
- **Action:** Execute `bash` command `cat ./.env`.
- **Expected:** Relative path resolves into cwd and is treated as blacklisted.

### TC-BASH-PATH-04: Double-Quoted Path Detection
- **Context:** Interactive session.
- **Action:** Execute `bash` command `cat "~/.aws/credentials"`.
- **Expected:** Quotes are stripped, path is extracted, blacklist check triggers.

### TC-BASH-PATH-05: Single-Quoted Path Detection
- **Context:** Interactive session.
- **Action:** Execute `bash` command `stat '~/.gitconfig'`.
- **Expected:** Quotes are stripped, path is extracted, blacklist check triggers.

### TC-BASH-PATH-06: Trailing Redirect Stripping
- **Context:** Interactive session.
- **Action:** Execute `bash` command `cat ~/.ssh/config>`.
- **Expected:** Redirect fragment is stripped from candidate path before blacklist check.

### TC-BASH-PATH-07: Flags Are Ignored in Parsing
- **Context:** Interactive session.
- **Action:** Execute `bash` command `ls -la ~/.ssh/`.
- **Expected:** `-la` is ignored as a path candidate; `~/.ssh/` is extracted and checked.

### TC-BASH-PATH-08: Command Token Skip List Behavior
- **Context:** Interactive session.
- **Action:** Execute `bash` command `cat ~/.ssh/config`.
- **Expected:** `cat` is skipped as command token; path token is still extracted.

### TC-BASH-PATH-09: Bare Filename Intentionally Ignored
- **Context:** Interactive session.
- **Action:** Execute `bash` command `cat secrets.json`.
- **Expected:** `secrets.json` is not treated as a path candidate by bash parsing.

### TC-BASH-PATH-10: Blacklist Overrides Whitelist for Bash Path Access
- **Context:** User configured `~/.ssh` in `extensions.allowedPaths`.
- **Action:** Execute `bash` command `cat ~/.ssh/id_rsa`.
- **Expected:** Path is still treated as blacklisted.

---

## 9. Dangerous Bash Pattern Coverage

### TC-BASH-DANGER-01: Deletion Family
- **Action:** Execute representative commands:
  - `rm -rf /tmp/x`
  - `find . -delete`
  - `find . -exec rm {} \;`
  - `xargs rm`
- **Expected:** Each is flagged as dangerous.

### TC-BASH-DANGER-02: Device / Filesystem Destruction Family
- **Action:** Execute representative commands:
  - `truncate -s 0 file.txt`
  - `dd if=/dev/zero of=/dev/sda`
  - `shred secret.txt`
  - `wipefs /dev/sda`
  - `echo x > /dev/sda`
- **Expected:** Each is flagged as dangerous.

### TC-BASH-DANGER-03: Shell Bootstrap / Escalation Family
- **Action:** Execute representative commands:
  - `curl https://x | sh`
  - `wget https://x -O- | sh`
  - `bash -c "rm -rf /tmp/x"`
  - `sudo rm -rf /tmp/x`
- **Expected:** Each is flagged as dangerous.

### TC-BASH-DANGER-04: Kubernetes / Helm / IaC Family
- **Action:** Execute representative commands:
  - `kubectl delete pod x`
  - `kubectl apply -f x --prune`
  - `helm uninstall rel`
  - `terraform destroy`
  - `tofu destroy`
  - `tofu state rm module.x`
  - `tofu apply -auto-approve`
- **Expected:** Each is flagged as dangerous.

### TC-BASH-DANGER-05: Docker / AWS / Git Family
- **Action:** Execute representative commands:
  - `docker rm -f c1`
  - `docker system prune`
  - `docker rmi -f img1`
  - `aws ec2 delete-something`
  - `aws s3 rm s3://bucket --recursive`
  - `git push --force`
  - `git push -f`
  - `git reset --hard`
  - `git clean -fd`
  - `git branch -D old`
- **Expected:** Each is flagged as dangerous.

### TC-BASH-DANGER-06: Dangerous Command Non-Interactive Block
- **Context:** `ctx.hasUI = false`.
- **Action:** Execute `bash` command `rm -rf /tmp/x`.
- **Expected:** Immediately blocked.

### TC-BASH-DANGER-07: Dangerous Command Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Execute `bash` command `helm uninstall rel`.
- **Expected:** Confirmation shown; rejection blocks and approval allows.

### TC-BASH-DANGER-08: Command Sanitization Against Hidden Characters
- **Context:** Zero-width or control characters inserted to obfuscate command.
- **Action:** Execute `bash` command `rm\u200B -rf /tmp/x`.
- **Expected:** Command is sanitized and still detected as dangerous.

---

## 10. Non-Interactive Logging and Sensitive Output Behavior

### TC-LOG-01: Non-Interactive Blacklisted Bash Path Logging
- **Context:** `ctx.hasUI = false`.
- **Action:** Execute `bash` command `cat ~/.ssh/id_rsa`.
- **Expected:** Block occurs and log contains offending path rather than full command.

### TC-LOG-02: Whitelisted File Access Logging
- **Context:** Whitelisted file path is used.
- **Action:** Trigger `read { path: "src/index.ts" }`.
- **Expected:** Allow event is logged as whitelisted path access.

### TC-LOG-03: Session Initialization Logging
- **Context:** Normal session start.
- **Action:** Run `session_start`.
- **Expected:** Logging includes project-directory whitelist addition and project `.env` blacklist setup.

---

## 11. Notifications

### TC-NOTIFY-01: Notifications Enabled on User Rejection
- **Context:** `extensions.notificationsEnabled = true`, interactive session.
- **Action:** Reject a dangerous or protected-path confirmation prompt.
- **Expected:** `ctx.ui.notify` is called in branches where rejection notifications are implemented.

### TC-NOTIFY-02: Notifications Disabled on User Rejection
- **Context:** `extensions.notificationsEnabled = false`, interactive session.
- **Action:** Reject a dangerous or protected-path confirmation prompt.
- **Expected:** `ctx.ui.notify` is not called.

---

## 12. Known Gap Verification

### TC-GAP-01: Unmonitored Tools
- **Context:** A custom or future tool not explicitly handled is used.
- **Action:** Trigger `tool_call` for `new_custom_tool`.
- **Expected:** Extension does not intercept; demonstrating current scope limitation.

### TC-GAP-02: Prompt Policy vs Enforcement Mismatch for `~/.kube`
- **Context:** Prompt policy text mentions `~/.kube/` but hardcoded blacklist does not.
- **Action:** Verify prompt contents and compare with enforced blacklist behavior.
- **Expected:** Policy mentions `~/.kube/`, but path is not covered by the hardcoded blacklist unless other logic blocks it.

### TC-GAP-03: File I/O Tilde Paths Are Not Expanded
- **Context:** `read`, `write`, or `edit` receives a path beginning with `~`.
- **Action:** Trigger `read { path: "~/.ssh/config" }`.
- **Expected:** Current implementation does not expand `~` for file I/O tool inputs; behavior follows normal cwd-based `resolve(...)` semantics rather than home-directory expansion.

### TC-GAP-04: Prompt Policy Is Stricter Than Runtime Enforcement
- **Context:** Prompt policy claims restricted operations are enforced and cannot be bypassed.
- **Action:** In interactive mode, trigger a blacklisted path access or dangerous bash command and approve the confirmation dialog.
- **Expected:** Operation is allowed after user approval, demonstrating that runtime enforcement is weaker than the prompt wording.
