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
   - Always blocked immediately, regardless of whether UI is available.
   - No user override is possible.
2. **WHITELIST** — lower priority than blacklist
   - Automatically allowed.
   - Applies to file I/O tools (`read`, `write`, `edit`) only. Bash commands are not checked against the whitelist.
3. **OPTIONAL CONSENT GATES**
   - Disabled by default: operations that would otherwise require consent proceed without prompting.
   - When `extensions.permissionGatesEnabled` is `true` or `"on"`, explicit user confirmation is required. Blocked if confirmation cannot be obtained.
   - Unconditional protections (blacklist, path traversal, and `node_modules` guards) are unaffected.

### 3.1. Precedence rule
If a path matches both blacklist and whitelist logic, **blacklist wins**.

## 4. Initialization and Lifecycle

### 4.1. Initial blocked state
Before configuration has finished loading during `session_start`, all monitored tool calls are blocked with reason:
- `Configuration not fully loaded`

### 4.2. Session start responsibilities
On `session_start`, the extension:
- determines effective current working directory (`resolve(ctx.cwd || process.cwd())`)
- discovers confirmed `node_modules` directories once (see section 6.6)
- appends security policy text to `ctx.systemPrompt` if present
- appends security policy text to `ctx.aiSystemMessage` if present
- attempts to load configuration
- validates configuration
- merges base allowed paths with configured allowed paths
- adds project directory to the whitelist
- rebuilds runtime whitelist regexes
- appends project-specific `.env` blacklist entries and discovered `node_modules` paths
- marks configuration as loaded

## 5. Configuration Behavior

### 5.1. Config file lookup precedence
Configuration is loaded from the first existing file in this order:
1. `<CWD>/.pi/settings.json`
2. `<ParentDir>/pi/agent/settings.json`
3. `<ParentDir>/pi/settings.json`

This existing lookup remains unchanged for allowed paths and notifications.

For the approval toggle only, an explicit value in the selected config takes precedence. If omitted, the toggle is read from Pi's global `~/.pi/agent/settings.json` (or `<PI_CODING_AGENT_DIR>/settings.json` when overridden). A project settings file that omits the toggle therefore inherits the global toggle. Invalid selected configuration or a parse/load failure leaves gates off.

### 5.2. Supported config keys
The extension reads these exact keys:
- `extensions.allowedPaths`
- `extensions.notificationsEnabled`
- `extensions.permissionGatesEnabled` — boolean or `"on"`/`"off"`; default `false`

These are literal dotted JSON keys, not nested objects. Enable approval gates in Pi's `settings.json`:

```json
{
  "extensions.permissionGatesEnabled": true
}
```

`"on"` also enables gates; `false`, `"off"`, or no setting disables them. Changes apply at session start or `/reload`. This toggle affects dangerous bash command approval and non-whitelisted `read`/`write`/`edit` approval only; protected paths still block without asking the user.

### 5.3. Validation rules
Configuration validation enforces:
- config must be an object
- config must not be `null`
- config must not be an array
- `extensions.allowedPaths`, if present, must be an array
- every element of `extensions.allowedPaths`, if present, must be a string
- `extensions.notificationsEnabled`, if present, must be a boolean
- `extensions.permissionGatesEnabled`, if present, must be a boolean or exactly `"on"`/`"off"`; strings `"true"`/`"false"`, numbers, and other values are invalid
- the permission toggle is reset to `false` before every session configuration load, preventing stale opt-in

### 5.4. Validation failure behavior
If validation fails:
- validation errors are logged
- invalid config values are not applied
- runtime continues using defaults / previously prepared safe values

### 5.5. Parse/load failure fallback behavior
If config loading or parsing throws an error:
- the extension logs the failure
- notifications are reset to `true`
- permission gates are reset to `false`
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

Tilde handling:
- tilde expansion is implemented for configured allowed paths
- tilde expansion is also implemented for bash path extraction
- tilde expansion is implemented for `read` / `write` / `edit` tool input paths before resolution

### 6.4. Runtime whitelist rebuilding
The exported `WHITELIST` array is mutable and is fully rebuilt during each `session_start` based on merged allowed paths.

### 6.5. Runtime blacklist management
The exported `BLACKLIST` array is mutable. At each `session_start`, it is reset to the base hardcoded blacklist entries and then augmented with project-specific `.env` entries for the current working directory and boundary-safe regexes for each discovered `node_modules` path. This ensures that blacklist entries from previous sessions do not accumulate.

### 6.6. Bounded `node_modules` discovery
At the beginning of each `session_start`, before configuration loading can fail, the extension performs one bounded filesystem discovery:

1. **Candidates checked:** `<cwd>/node_modules`, `<parent-of-cwd>/node_modules`, and `<cwd>/<immediate-child>/node_modules` for each immediate child directory of the CWD (excluding a child literally named `node_modules`).
2. **Out of scope:** grandparent `node_modules`, deeper descendants such as `<cwd>/packages/ui/node_modules`, recursive traversal, workspace manifest parsing, and per-tool-call rediscovery.
3. **Confirmation rule:** only paths where `statSync` reports a directory are retained. A regular file named `node_modules` is ignored. A final `node_modules` symlink to a directory counts; discovered paths remain lexical (no `realpath()` canonicalization).
4. **Error handling:** `statSync` or `readdirSync` failures treat the affected candidate or listing as absent. Discovery errors do not fail session initialization.
5. **Session snapshot:** discovery results are stored for the session and are not refreshed until the next `session_start`. Dependency changes after initialization may leave protection stale until restart.

### 6.7. Direct protection for discovered `node_modules`
Every confirmed discovery path is added to the shared runtime blacklist as an **exact-root** entry used by `bash`, `read`, `write`, and `edit`. Regex entries are escaped and boundary-safe so `/path/node_modules` matches while `/path/node_modules_backup` and `/path/node_modules/pkg/...` do not match the shared blacklist.

**Specific-package exception (bash and read only):** paths that name at least one segment under a discovered install (for example `/path/node_modules/lodash/index.js` or `/path/node_modules/@scope/pkg/README.md`) are not blocked by the shared blacklist, so inspection and package-targeted bash commands are allowed.

**write/edit remain fully blocked:** `write` and `edit` additionally reject any path under a discovered `node_modules` tree (exact root and all descendants), including specific package paths.

### 6.8. Pass 2 project-root `find` gating
When a confirmed `node_modules` location lies in the CWD tree (`<cwd>/node_modules` or an immediate-child install), Pass 2 blocks unexcluded project-root **`find`** commands rooted at `.`, `./`, the CWD, or the CWD with a trailing separator. Unexcluded `rg` and recursive `grep` are **not** gated by Pass 2 (they are allowed through for agent usability; `rg` often already respects `.gitignore`).

Parent-only discoveries blacklist the parent `node_modules` **root** for direct access but do **not** activate Pass 2, because CWD-root scans do not walk upward. Specific package paths under a parent install follow the same bash/read exception as CWD-tree installs.

**Pass 1 carve-out for prune operands:** exact discovered `node_modules` roots are ignored by Pass 1 only when they appear as `-path <root> -prune` operands (for example `find . -path ./packages/node_modules -prune …`). A generic exclusion flag elsewhere in the command does **not** unlock browsing or reading the exact root. Other blacklisted paths in the same command still block.

Bash inspection remains regex-based, not a complete shell parser.

Pass 2 exists to stop expensive/noisy project-root `find` walks when CWD-tree dependencies are present. It does not guarantee that a blocked agent will retry with an exclusion; agents may pivot to `ls` or manual exploration instead.

### 6.9. Accepted `node_modules` exclusion forms
When Pass 2 is active, an exclusion is recognized when:
- a `find -path <discovered-root> -prune` names any discovered install (for example `./node_modules` or `./packages/node_modules`), or
- a `find -not -path '<discovered-root>/*'` form names any discovered install

Literal `./node_modules` prune does **not** satisfy Pass 2 when the only discovered install is an immediate child (for example `packages/node_modules`); the prune path must match a discovered root.

Content-search flags such as `rg --glob '!node_modules/**'` or `grep --exclude-dir=node_modules` are **not** Pass 2 exclusions (Pass 2 does not gate `rg`/`grep`, and those flags do not cause `find` to skip `node_modules`).

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

### 8.3. Bash evaluation order
For bash commands, the extension evaluates in this fixed order:
1. **Blacklist path detection** — if any extracted path argument matches the blacklist, the command is blocked immediately, regardless of whether the command is also dangerous. No user override is possible, except that an exact discovered `node_modules` root may be a target of an otherwise-qualified project-local deletion. Exact discovered `node_modules` roots are also skipped when they appear as `-path <root> -prune` operands (Pass 1 carve-out).
2. **Conditional project-root `find` guard (Pass 2)** — when CWD-tree `node_modules` was discovered at session start, blocks unexcluded `find` rooted at `.`, `./`, the CWD, or the CWD with a trailing separator. Unexcluded `rg` / recursive `grep` are not gated. Skipped when no CWD-tree install was discovered or when an accepted find exclusion referencing a discovered root is present.
3. **Project-local deletion allowance** — a direct filesystem deletion command (`rm`, `unlink`, `rmdir`, or `shred`) is allowed without confirmation when all explicit targets resolve strictly inside the project directory. This allowance supports command chains that first `cd` into a project subdirectory. Sensitive paths, including project `.env` files and static blacklist entries, remain blocked; unknown shell expansions and hidden-file globs do not qualify.
4. **Dangerous pattern detection** — only reached if no blacklisted path was found, Pass 2 did not block, and the project-local deletion allowance did not apply. This check is skipped when permission gates are off. When enabled and a dangerous pattern is detected, user confirmation is required to proceed. Blocked if confirmation cannot be obtained.

The whitelist is intentionally not consulted for bash commands. Any bash command that passes all checks above is allowed to proceed regardless of whether its path arguments are whitelisted.

### 8.4. Bash path extraction purpose
The extension extracts path-like arguments from all bash commands and checks them against blacklist rules. This applies to both read-like and destructive commands, ensuring that dangerous commands targeting blacklisted paths are caught at the blacklist check rather than the dangerous-command confirmation flow.

## 9. Bash Path Extraction Rules
The bash parser:
- tokenizes on shell-like separators such as whitespace, `;`, `|`, and `&`
- trims tokens
- strips surrounding single or double quotes
- strips trailing shell redirect/operator fragments from candidate tokens
- skips option-like tokens beginning with `-`
- skips known command/program names from `COMMAND_NAME_TOKENS`
- does **not** treat that token list as a security policy list; it is only a parsing skip list
- intentionally does **not** include `.` in the skip list
- extracts explicit path shapes:
  - `~`
  - `~/...`
  - `/...`
  - `./...`
  - `../...`
- additionally extracts conservative bare/path-like tokens (for example `.env`, `.env.local`, `config.json`, `dir/file.txt`)
- resolves explicit relative paths and extracted bare/path-like tokens against cwd
- applies conservative bare-token filters to reduce false positives (for example skipping URLs, variable-prefixed tokens, `key=value` assignments, and glob-like tokens)

### 9.1. Consequence of parser conservatism
Because bare-token extraction is heuristic and intentionally conservative, some complex shell expressions may still evade path extraction unless they are represented as direct path-like tokens.

## 10. File I/O Protection (`read`, `write`, and `edit`)

### 10.1. Path traversal detection
Before path resolution, the extension blocks paths matching traversal semantics using `..` at path-segment boundaries.

### 10.2. False-positive avoidance
Traversal detection is intentionally narrower than a raw substring check and should not block benign filenames containing `..` internally, such as:
- `..config`
- `my..file`

### 10.3. Resolution behavior
For monitored file I/O tools:
- the supplied path is tilde-expanded first (for `~`-prefixed inputs)
- the expanded path is resolved against effective cwd
- the resolved path is checked through blacklist-first security logic

### 10.4. Decision behavior for file I/O
For `read`, `write`, and `edit`:
- blacklist match:
  - blocked immediately, regardless of mode
  - no user override is possible
- whitelist match:
  - allowed automatically
- neither blacklist nor whitelist:
  - allowed without prompting when permission gates are off (default)
  - when gates are enabled, requires user confirmation to proceed; blocked if confirmation cannot be obtained
- path traversal and discovered `node_modules` mutation blocks remain unconditional

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

### 11.4. Prompt-policy alignment
Blacklisted path access is strictly enforced at runtime: it is blocked immediately with no user override, matching the prompt policy claim that these restrictions cannot be bypassed.

Dangerous bash commands that do not target a blacklisted path are allowed without prompting when permission gates are off. When gates are enabled, interactive user approval is required. The path restrictions in the prompt remain unconditional.

## 12. User Interaction, Notifications, and Logging

### 12.1. Interactive approval flow
Permission gates are off by default. When enabled, all confirmation prompts are awaited before allowing execution to proceed. Protected-path blocks never prompt or offer user override, regardless of this setting.

### 12.2. Notification behavior
Notifications are shown only in user-rejection branches where notification logic is implemented, and only if `notificationsEnabled` is `true`.

### 12.3. Non-interactive behavior
When permission gates are enabled, operations that require user confirmation are blocked when confirmation cannot be obtained (e.g., no UI available). When gates are off, these approval-only operations proceed even without a UI; unconditional protections remain active.

### 12.4. Logging behavior
Observable logging includes, at minimum:
- configuration validation success/failure
- config load failure
- blocked dangerous commands in non-interactive mode
- user rejection of dangerous commands
- blocked blacklisted-path access (all modes)
- automatic allow of whitelisted file paths
- project directory addition to whitelist
- project `.env` blacklist setup

### 12.5. Sensitive logging nuance
For bash access to a blacklisted path, logging records the offending path rather than the full command to reduce leakage risk.

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
- approval-only operations are allowed by default; opting into permission gates adds user consent checks but does not change protected-path enforcement
- bash path extraction is heuristic and may miss complex shell-expanded references
- `node_modules` discovery is bounded to CWD, one parent, and immediate CWD children; grandparent installs and deeper workspace layouts are not discovered from the workspace root
- discovery is a session snapshot and may be stale after dependency installation or removal until the next `session_start`
- only lexical discovered paths are protected; symlink aliases outside the discovered set are not covered
- Pass 2 does not steer models toward exclusion retries; blocked agents may switch to `ls` or manual exploration
- Pass 2 gates project-root `find` only; unexcluded `rg` / `grep -R` may still walk `node_modules` when those tools do not self-ignore
