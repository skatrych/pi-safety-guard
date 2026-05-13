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

### TC-INIT-07: Repeated Session Reset Behavior
- **Context:** Same extension instance handles multiple `session_start` events in one process.
- **Action:** Run `session_start` for cwd `/prj/app`, then run `session_start` again for cwd `/prj/other`.
- **Expected:** Runtime blacklist keeps static built-in entries and exactly one project-specific `.env` pair for the current cwd (`/prj/other`). Entries for `/prj/app` are no longer present.

### TC-INIT-08: Project `node_modules` Blacklist Added
- **Context:** Session starts with cwd `/prj/app`.
- **Action:** Run `session_start`.
- **Expected:** Runtime blacklist gains a pattern that blocks `/prj/app/node_modules` and all descendants.

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
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `read` for each representative absolute home-based path:
  - `<HOME>/.pi/agent/auth.json`
  - `<HOME>/.ssh/id_rsa`
  - `<HOME>/.gnupg/pubring.kbx`
  - `<HOME>/Library/Keychains/login.keychain-db`
  - `<HOME>/.aws/credentials`
  - `<HOME>/.kube/`
  - `<HOME>/Pictures/Photos Library.photoslibrary/database`
  - `<HOME>/.env`
  - `<HOME>/.env.local`
  - `<HOME>/.gitconfig`
- **Expected:** Each path is treated as blacklisted and blocked immediately, regardless of mode. No confirmation prompt is shown.

### TC-PATH-02: System Paths
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `read` for representative paths under `/etc/`, `/usr/`, and `/System/`.
- **Expected:** Each path is treated as blacklisted and blocked immediately. No confirmation prompt is shown.

### TC-PATH-03: Base Whitelist Paths
- **Context:** Session initialized.
- **Action:** Trigger `read` under:
  - `<HOME>/.pi/`
  - `/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/`
- **Expected:** Access is allowed automatically unless a more specific blacklist rule applies.

### TC-PATH-04: Blacklist Overrides Whitelist for File I/O
- **Context:** User has configured `~/.ssh` inside `extensions.allowedPaths`.
- **Action:** Trigger `read <HOME>/.ssh/config`.
- **Expected:** Blacklist still wins; operation is blocked immediately with no confirmation prompt.

---

## 5. File I/O Protection - `read`

### TC-READ-01: Whitelisted Read Allowed
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `read { path: "src/index.ts" }`.
- **Expected:** Resolved path is inside project whitelist; access is allowed automatically.

### TC-READ-02: Blacklisted Read Strict Block
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `read { path: "<HOME>/.ssh/config" }`.
- **Expected:** Blocked immediately; no confirmation prompt is shown regardless of mode.

### TC-READ-03: Consent-Required Read Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `read { path: "/tmp/report.txt" }`.
- **Expected:** Consent prompt shown; rejection blocks, approval allows.

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
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `read { path: "<HOME>/.env.local" }`.
- **Expected:** Blacklisted; blocked immediately with no confirmation prompt.

### TC-READ-10: Project `.env` Variant Protection Matrix
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `read` for:
  - `.env`
  - `.env.local`
  - `packages/api/.env`
  - `apps/web/.env.production`
- **Expected:** Each path is treated as blacklisted by project-specific runtime rules and blocked immediately.

### TC-READ-11: Project `node_modules` Read Block
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `read` for:
  - `node_modules/pkg/index.js`
  - `./node_modules/pkg/package.json`
- **Expected:** Each resolves under `/prj/app/node_modules` and is blocked immediately as blacklisted.

---

## 6. File I/O Protection - `write`

### TC-WRITE-01: Whitelisted Write Allowed
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `write { path: "out/report.txt" }`.
- **Expected:** Allowed automatically.

### TC-WRITE-02: Blacklisted Write Strict Block
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `write { path: "<HOME>/.ssh/config" }`.
- **Expected:** Blocked immediately; no confirmation prompt is shown regardless of mode.

### TC-WRITE-03: Consent-Required Write Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `write { path: "/tmp/output.txt" }`.
- **Expected:** Consent prompt shown; rejection blocks, approval allows.

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

### TC-EDIT-02: Blacklisted Edit Strict Block
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `edit { path: "<HOME>/.ssh/config", edits: [...] }`.
- **Expected:** Blocked immediately; no confirmation prompt is shown regardless of mode.

### TC-EDIT-03: Consent-Required Edit Interactive Approve/Reject
- **Context:** Interactive session.
- **Action:** Trigger `edit { path: "/tmp/report.txt", edits: [...] }`.
- **Expected:** Consent prompt shown; rejection blocks, approval allows.

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
- **Context:** Any session (interactive or non-interactive).
- **Action:** Trigger `edit { path: "<HOME>/.env.local", edits: [...] }`.
- **Expected:** Blacklisted; blocked immediately with no confirmation prompt.

### TC-EDIT-09: Edit Project `.env` Variant Protection Matrix
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Trigger `edit` for:
  - `.env`
  - `.env.local`
  - `packages/api/.env`
- **Expected:** Each path is treated as blacklisted by project-specific runtime rules and blocked immediately.

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
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `cat ~/.ssh/id_rsa`.
- **Expected:** Path is extracted, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-02: Absolute Path Detection
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `ls -la /etc/passwd`.
- **Expected:** Path is extracted, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-03: Explicit Relative Path Detection
- **Context:** Session initialized with cwd `/prj/app` and project `.env` blacklist active.
- **Action:** Execute `bash` command `cat ./.env`.
- **Expected:** Relative path resolves into cwd, is treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-04: Double-Quoted Path Detection
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `cat "~/.aws/credentials"`.
- **Expected:** Quotes are stripped, path is extracted, blacklist match triggers, and command is blocked immediately.

### TC-BASH-PATH-05: Single-Quoted Path Detection
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `stat '~/.gitconfig'`.
- **Expected:** Quotes are stripped, path is extracted, blacklist match triggers, and command is blocked immediately.

### TC-BASH-PATH-06: Redirect Target Path Detection (Whitespace and No-Whitespace Forms)
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute:
  - `echo x > /etc/test.conf`
  - `echo x >/etc/test.conf`
  - `cat < /etc/hosts`
  - `cat </etc/hosts`
- **Expected:** Redirect target paths are extracted structurally and commands are blocked immediately.

### TC-BASH-PATH-07: Flags Are Ignored in Parsing
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `ls -la ~/.ssh/`.
- **Expected:** `-la` is ignored as a path candidate; `~/.ssh/` is extracted, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-08: Command Token Skip List Behavior
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `cat ~/.ssh/config`.
- **Expected:** `cat` is skipped as command token; path token is extracted, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-09: Bare Filename Detection (`.env`)
- **Context:** Session initialized with cwd `/prj/app` and project `.env` blacklist active.
- **Action:** Execute `bash` command `cat .env`.
- **Expected:** Bare token `.env` is treated as a path candidate, resolves to `/prj/app/.env`, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-10: Blacklist Overrides Whitelist for Bash Path Access
- **Context:** User configured `~/.ssh` in `extensions.allowedPaths`.
- **Action:** Execute `bash` command `cat ~/.ssh/id_rsa`.
- **Expected:** Path is still treated as blacklisted and command is blocked immediately.

### TC-BASH-PATH-11: Bare Filename Detection (`.env.local`)
- **Context:** Session initialized with cwd `/prj/app` and project `.env` blacklist active.
- **Action:** Execute `bash` command `cat .env.local`.
- **Expected:** Bare token `.env.local` is treated as a path candidate, resolves to `/prj/app/.env.local`, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-12: Bare Relative Subpath Detection
- **Context:** Session initialized with cwd `/prj/app` and project `.env` blacklist active.
- **Action:** Execute `bash` command `cat packages/api/.env`.
- **Expected:** Bare subpath token is treated as a path candidate, resolves to `/prj/app/packages/api/.env`, treated as blacklisted, and command is blocked immediately.

### TC-BASH-PATH-13: Conservative Bare-Token Filtering
- **Context:** Interactive session.
- **Action:** Execute `bash` command `echo package-name`.
- **Expected:** `package-name` is not treated as a path candidate by bash parsing.

### TC-BASH-PATH-14: Recursive Project Root `find` Block Without Exclusion
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Execute `bash` command `find . -type f`.
- **Expected:** Blocked with reason requiring explicit `node_modules` exclusion.

### TC-BASH-PATH-15: Recursive Project Root `grep -R` Block Without Exclusion
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Execute `bash` command `grep -R TODO .`.
- **Expected:** Blocked with reason requiring explicit `node_modules` exclusion.

### TC-BASH-PATH-16: Recursive Project Root `rg` Block Without Exclusion
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Execute `bash` command `rg TODO .`.
- **Expected:** Blocked with reason requiring explicit `node_modules` exclusion.

### TC-BASH-PATH-17: Recursive Project Root Scan Allowed With Exclusion
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Execute one of:
  - `find . -path ./node_modules -prune -o -type f -print`
  - `grep -R --exclude-dir=node_modules TODO .`
  - `rg --glob '!node_modules/**' TODO .`
- **Expected:** Not blocked by the recursive-scan guard (normal safety checks continue).

### TC-BASH-PATH-18: Pi Self-Knowledge Path Under Global `node_modules` Remains Allowed
- **Context:** Session initialized with cwd `/prj/app`.
- **Action:** Execute one of:
  - `find /opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent -maxdepth 2 -type f`
  - `grep -R "ExtensionContext" /opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/README.md`
- **Expected:** Not blocked by project `node_modules` blacklist or recursive project-root scan guard.

### TC-BASH-PATH-19: Heredoc Body Mention of Blacklisted Paths Does Not Block
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute:
  - `cat <<'EOF'\nprint('/etc/passwd')\nprint('~/.ssh/id_rsa')\nEOF`
- **Expected:** No blacklist block is triggered from heredoc body text alone.

### TC-BASH-PATH-20: Regression Reproduction From `bug-summary.md`
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute the exact command payload from `bug-summary.md`.
- **Expected:** The command is not blocked by blacklisted-path detection based solely on heredoc payload text.

### TC-BASH-PATH-21: Tab-Stripping Heredoc Still Parses Later Operands
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute:
  - `cat <<-EOF\nbody\nEOF\ncat /etc/passwd`
- **Expected:** Heredoc body content is ignored, the `EOF` terminator is recognized for `<<-`, and the later `/etc/passwd` operand is still extracted and blocked.

### TC-BASH-PATH-22: Quoted Code String vs Quoted Real Path Operand
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute:
  - `python3 -c "print('/etc/passwd')"`
  - `cat "/etc/passwd"`
- **Expected:** First command is not blocked by path extraction alone; second command is blocked as direct blacklisted path access.

### TC-BASH-PATH-23: Concatenated Quoted Path Fragments Still Count As Real Operands
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute:
  - `cat "/etc"/passwd`
  - `cat "./dir"/../.env`
- **Expected:** Quote removal happens at the shell-word level, so both operands are reconstructed structurally and blocked as real path access.

### TC-BASH-PATH-24: Background Operator Continues Parsing Later Operands
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo hi & cat /etc/passwd`.
- **Expected:** Parsing completes without hanging; later `/etc/passwd` operand is extracted and blocked.

### TC-BASH-PATH-25: Background Operator Without Paths Does Not Hang
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo hi & echo bye`.
- **Expected:** Parsing completes without hanging and no path candidate is produced.

### TC-BASH-PATH-26: Fd-Dup Redirect Does Not Hang and Keeps Earlier Path Detection
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `cat /etc/passwd 2>&1`.
- **Expected:** Parsing completes without hanging; `/etc/passwd` is extracted and blocked.

### TC-BASH-PATH-27: Fd-Dup Redirect Alone Does Not Produce False Path Candidates
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo hi 2>&1`.
- **Expected:** Parsing completes without hanging and the redirect syntax does not create path candidates.

### TC-BASH-PATH-28: Fd-Dup Redirect Followed by Separator Still Allows Later Path Extraction
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo hi 2>&1; cat /etc/passwd`.
- **Expected:** Parsing completes without hanging; later `/etc/passwd` operand is extracted and blocked.

### TC-BASH-PATH-29: Comment Body Mention of Blacklisted Path Does Not Block
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo ok # /etc/passwd`.
- **Expected:** Text after `#` is treated as comment and does not produce path candidates or block.

### TC-BASH-PATH-30: Real Operand Before Comment Still Blocks
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `cat /etc/passwd # comment`.
- **Expected:** Real operand before comment is extracted and blocked.

### TC-BASH-PATH-31: Comment Immediately After Operator Does Not Block
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo ok;# /etc/passwd`.
- **Expected:** `#` starts a comment at a word boundary after `;`; comment text does not produce path candidates or block.

### TC-BASH-PATH-32: Literal Hash Inside a Word Stays Literal
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo foo#bar`.
- **Expected:** `foo#bar` remains a normal word token and does not trigger comment truncation.

### TC-BASH-PATH-33: Quoted Hash Does Not Start a Comment
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `echo "# /etc/passwd"`.
- **Expected:** Quoted `#` remains literal content and does not create comment truncation or path extraction.

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

### TC-BASH-DANGER-08: Dangerous Command Targeting Blacklisted Path
- **Context:** Any session (interactive or non-interactive).
- **Action:** Execute `bash` command `rm -rf ~/.ssh/`.
- **Expected:** The operation is blocked, no confirmation prompt appears, and the block reason identifies the blacklisted path.

### TC-BASH-DANGER-09: Command Sanitization Against Hidden Characters
- **Context:** Zero-width or control characters inserted to obfuscate command.
- **Action:** Execute `bash` command `rm\u200B -rf /tmp/x` (targets non-blacklisted path).
- **Expected:** Command is sanitized and still detected as dangerous.

---

## 10. Non-Interactive Logging and Sensitive Output Behavior

### TC-LOG-01: Blacklisted Bash Path Logging
- **Context:** Any session (interactive or non-interactive).
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

### TC-NOTIFY-01: Notifications Enabled on User Rejection of Dangerous Command
- **Context:** `extensions.notificationsEnabled = true`, interactive session.
- **Action:** Reject a dangerous bash command confirmation prompt (e.g., `helm uninstall rel`).
- **Expected:** `ctx.ui.notify` is called. Note: blacklisted-path operations are blocked immediately without a user prompt and do not produce rejection notifications.

### TC-NOTIFY-02: Notifications Disabled on User Rejection of Dangerous Command
- **Context:** `extensions.notificationsEnabled = false`, interactive session.
- **Action:** Reject a dangerous bash command confirmation prompt.
- **Expected:** `ctx.ui.notify` is not called.

---

## 12. Known Gap Verification

### TC-GAP-01: Unmonitored Tools
- **Context:** A custom or future tool not explicitly handled is used.
- **Action:** Trigger `tool_call` for `new_custom_tool`.
- **Expected:** Extension does not intercept; demonstrating current scope limitation.

### TC-GAP-02: File I/O Tilde Paths Are Correctly Expanded and Protected
- **Context:** `read`, `write`, or `edit` receives a path beginning with `~`.
- **Action:** Trigger `read { path: "~/.ssh/config" }`.
- **Expected:** `~` is expanded to the home directory before resolution and security checks; the resolved path matches the blacklist and the operation is blocked immediately with no confirmation prompt.

### TC-GAP-03: Partial Prompt Policy Alignment
- **Context:** Prompt policy claims restricted operations are enforced and cannot be bypassed.
- **Action:** In interactive mode, trigger a dangerous bash command that does not target a blacklisted path (e.g., `helm uninstall rel`) and approve the confirmation dialog.
- **Expected:** Operation is allowed after user approval, demonstrating that dangerous commands without blacklisted paths can still be approved in interactive mode. Note: blacklisted path access is now fully enforced and cannot be bypassed via confirmation.
