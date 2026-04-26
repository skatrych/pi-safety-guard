# Safety Guard Extension Requirements

## 1. Overview
The Safety Guard extension is a security-focused plugin for the Pi coding agent. It implements a layered defense-in-depth strategy to protect sensitive user data, prevent destructive operations, and enforce explicit consent for operations outside known-safe boundaries. It intercepts selected tool calls, augments the AI system prompt with a security policy, and applies a runtime path security model.

## 2. Scope and Tool Coverage

### 2.1. Monitored tools
The extension explicitly monitors only these tool calls:
- `bash`
- `read`
- `write`
- `edit`

### 2.2. Unmonitored tools
All other tools are currently outside the enforcement scope of this extension and pass through without intervention, including:
- any custom or future tools not explicitly handled

This is an important current limitation and security boundary.

## 3. Security Decision Model
The extension applies a strict priority model:

1. **BLACKLIST** — highest priority
   - Interactive mode: requires explicit user confirmation.
   - Non-interactive mode: blocked.
2. **WHITELIST** — lower priority than blacklist
   - Automatically allowed.
3. **DEFAULT / CONSENT REQUIRED**
   - Interactive mode: requires explicit user confirmation.
   - Non-interactive mode: blocked.

### 3.1. Precedence rule
If a path matches both blacklist and whitelist logic, **blacklist wins**.

## 4. Initialization and Lifecycle

### 4.1. Initial blocked state
Before configuration has finished loading during `session_start`, all monitored tool calls are blocked with reason:
- `Configuration not fully loaded`

### 4.2. Session start responsibilities
On `session_start`, the extension:
- determines effective current working directory (`ctx.cwd` or `process.cwd()`)
- appends security policy text to `ctx.systemPrompt` if present
- appends security policy text to `ctx.aiSystemMessage` if present
- attempts to load configuration
- validates configuration
- merges base allowed paths with configured allowed paths
- adds project directory to the whitelist
- rebuilds runtime whitelist regexes
- appends project-specific `.env` blacklist entries
- marks configuration as loaded

## 5. Configuration Behavior

### 5.1. Config file lookup precedence
Configuration is loaded from the first existing file in this order:
1. `<CWD>/.pi/settings.json`
2. `<ParentDir>/pi/agent/settings.json`
3. `<ParentDir>/pi/settings.json`

This is parent-relative lookup, not a generic global-home lookup.

### 5.2. Supported config keys
The extension reads these exact keys:
- `extensions.allowedPaths`
- `extensions.notificationsEnabled`

### 5.3. Validation rules
Configuration validation enforces:
- config must be an object
- config must not be `null`
- config must not be an array
- `extensions.allowedPaths`, if present, must be an array
- every element of `extensions.allowedPaths`, if present, must be a string
- `extensions.notificationsEnabled`, if present, must be a boolean

### 5.4. Validation failure behavior
If validation fails:
- validation errors are logged
- invalid config values are not applied
- runtime continues using defaults / previously prepared safe values

### 5.5. Parse/load failure fallback behavior
If config loading or parsing throws an error:
- the extension logs the failure
- notifications are reset to `true`
- allowed paths fall back to:
  - `~/.pi/`
  - `/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/`
  - effective cwd
- whitelist regexes are rebuilt from those fallback paths
- project `.env` blacklist entries are still added
- `configLoaded` is set to `true` so the extension does not remain permanently blocked

## 6. Path Security Model

### 6.1. Hardcoded blacklist entries
The extension hardcodes protection for these path families:
- `~/.pi/agent/auth.json`
- `~/.ssh/`
- `~/.gnupg/`
- `~/Library/Keychains/`
- `~/.aws/credentials`
- `~/.kube/`
- `~/Pictures/Photos Library.photoslibrary/`
- `~/.env`
- `~/.env.*`
- `~/.gitconfig`
- `/etc/`
- `/usr/`
- `/System/`

These blacklist entries are compiled using escaped home-directory-based regexes where relevant.

### 6.2. Base whitelist entries
The runtime whitelist always includes these base path families:
- `~/.pi/`
- `/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/`

Additionally, the effective project directory is added dynamically at session start.

### 6.3. User-defined allowed paths
Configured allowed paths from `extensions.allowedPaths` are:
- tilde-expanded
- merged with base whitelist paths
- deduplicated at string level before whitelist regex rebuild

Important distinction:
- tilde expansion is implemented for configured allowed paths
- tilde expansion is also implemented for bash path extraction
- tilde expansion is **not currently implemented** for `read` / `write` / `edit` tool input paths

### 6.4. Runtime whitelist rebuilding
The exported `WHITELIST` array is mutable and is fully rebuilt during each `session_start` based on merged allowed paths.

### 6.5. Runtime blacklist management
The exported `BLACKLIST` array is mutable. At each `session_start`, it is reset to the base hardcoded blacklist entries and then augmented with project-specific `.env` entries for the current working directory. This ensures that blacklist entries from previous sessions do not accumulate.

## 7. Project-Specific Secret Protection

### 7.1. Dynamic project `.env` protection
At session start, the extension appends blacklist protection for:
- `<cwd>/.env`
- `<cwd>/.env.*`
- nested `<cwd>/**/.env`
- nested `<cwd>/**/.env.*`

### 7.2. Implementation detail
This is implemented as two separate regex patterns:
- `^<cwd>/(?:.+/)?\.env$`
- `^<cwd>/(?:.+/)?\.env\.`

This behavior protects project-local secret files at arbitrary nesting depth.

## 8. Bash Command Protection

### 8.1. Command sanitization
Before inspection, bash commands are sanitized by removing:
- control characters in ranges `\u0000-\u001F` and `\u007F`
- zero-width characters `\u200B`, `\u200C`, `\u200D`

This is intended to reduce bypass opportunities.

### 8.2. Dangerous command pattern detection
The extension detects representative destructive or risky command families including:
- deletion and destructive file removal
  - `rm -rf`
  - `rm --recursive`
  - `rm --force`
  - `unlink`
  - `rmdir`
  - `find ... -exec rm`
  - `find ... -delete`
  - `xargs rm`
  - wildcard deletion forms
- destructive file/device operations
  - `truncate`
  - `dd` with disk-related arguments
  - `shred`
  - `wipefs`
  - redirects to raw block devices
- shell/bootstrap risk patterns
  - `curl | sh`
  - `wget | sh`
  - `bash -c ... rm`
  - `sudo ... rm`
  - fork bomb syntax
- infrastructure and platform destruction
  - `kubectl delete`
  - `kubectl apply ... --prune`
  - `helm uninstall`
  - `tofu destroy`
  - `terraform destroy`
  - `tofu state rm`
  - `tofu apply ... -auto-app...`
  - `docker rm -f`
  - `docker system prune`
  - `docker rmi -f`
  - `aws <service> delete`
  - `aws s3 rm ... --recursive`
- dangerous git operations
  - `git push -f`
  - `git push --force`
  - `git reset --hard`
  - `git clean -fd`
  - `git branch -D`

### 8.3. Dangerous bash decision behavior
If a dangerous bash pattern is detected:
- interactive mode: user confirmation is required
- non-interactive mode: operation is blocked

### 8.4. Bash path extraction purpose
For non-destructive but potentially sensitive bash commands, the extension extracts path-like arguments and checks them against blacklist rules to catch read-like access to protected paths.

## 9. Bash Path Extraction Rules
The bash parser:
- tokenizes on shell-like separators such as whitespace, `;`, `|`, and `&`
- trims tokens
- strips surrounding single or double quotes
- skips option-like tokens beginning with `-`
- skips known command/program names from `COMMAND_NAME_TOKENS`
- does **not** treat that token list as a security policy list; it is only a parsing skip list
- intentionally does **not** include `.` in the skip list
- extracts only explicit path shapes:
  - `~`
  - `~/...`
  - `/...`
  - `./...`
  - `../...`
- resolves explicit relative paths against cwd
- strips trailing shell redirect/operator fragments from extracted candidates
- intentionally ignores bare words such as `config.json` to reduce false positives

### 9.1. Consequence of parser conservatism
Because bare words are ignored, some file references in bash commands may not be detected by path extraction unless they use explicit path syntax.

## 10. File I/O Protection (`read`, `write`, and `edit`)

### 10.1. Path traversal detection
Before path resolution, the extension blocks paths matching traversal semantics using `..` at path-segment boundaries.

### 10.2. False-positive avoidance
Traversal detection is intentionally narrower than a raw substring check and should not block benign filenames containing `..` internally, such as:
- `..config`
- `my..file`

### 10.3. Resolution behavior
For monitored file I/O tools:
- the supplied path is resolved against effective cwd
- `read` / `write` / `edit` inputs are **not** tilde-expanded before resolution
- therefore a path beginning with `~` is not treated as a home-directory path by current implementation
- the resolved path is checked through blacklist-first security logic

### 10.4. Decision behavior for file I/O
For `read`, `write`, and `edit`:
- blacklist match:
  - interactive: confirmation required
  - non-interactive: blocked
- whitelist match:
  - allowed automatically
- neither blacklist nor whitelist:
  - interactive: confirmation required
  - non-interactive: blocked

### 10.5. Missing input behavior
If `read`, `write`, or `edit` input does not contain a usable string `path`, the extension returns without intervention.

## 11. Prompt Augmentation Behavior
The extension appends a security policy block to prompt fields if present.

### 11.1. Target fields
- `ctx.systemPrompt`
- `ctx.aiSystemMessage`

### 11.2. Preservation behavior
If a target field exists, the original content is preserved and the security policy text is appended.

### 11.3. Policy content themes
The appended policy communicates restrictions around:
- blacklisted filesystem locations
- `.env` files
- credentials and confidential directories
- AWS secrets / KMS / certificate keys
- Kubernetes secrets

### 11.4. Prompt-policy mismatch currently present
The prompt policy is stricter than runtime enforcement:
- the prompt policy states restrictions are enforced and cannot be bypassed, but runtime behavior still allows interactive user override for blacklisted paths and dangerous commands via confirmation dialogs

## 12. User Interaction, Notifications, and Logging

### 12.1. Interactive approval flow
All confirmation prompts are awaited before allowing execution to proceed.

### 12.2. Notification behavior
Notifications are shown only in user-rejection branches where notification logic is implemented, and only if `notificationsEnabled` is `true`.

### 12.3. Non-interactive behavior
In headless mode, operations requiring confirmation are blocked rather than silently allowed.

### 12.4. Logging behavior
Observable logging includes, at minimum:
- configuration validation success/failure
- config load failure
- blocked dangerous commands in non-interactive mode
- user rejection of dangerous commands
- user rejection of blacklisted-path access
- automatic allow of whitelisted file paths
- project directory addition to whitelist
- project `.env` blacklist setup

### 12.5. Sensitive logging nuance
For non-interactive bash access to a blacklisted path, logging records the offending path rather than the full command to reduce leakage risk.

## 13. Graceful No-Op Cases
The extension returns without intervention when:
- a monitored `bash` call has no `command`
- a monitored `read` call has no `path`
- a monitored `write` call has no `path`
- a monitored `edit` call has no usable string `path`
- an unmonitored tool is invoked

## 14. Known Gaps / Current Limitations
Current implementation limitations that should be preserved or intentionally addressed in refactoring:
- unmonitored tools are not protected
- prompt policy is stricter than runtime enforcement because interactive confirmation can still allow blacklisted paths and dangerous commands
- bash path extraction ignores bare filenames
