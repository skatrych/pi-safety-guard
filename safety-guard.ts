/**
 * Safety Guard Extension
 *
 * Comprehensive safety guardian using Whitelist/Blacklist model:
 * - BLACKLIST: Highest priority - blocked unconditionally (creds/confidential)
 * - WHITELIST: Lower priority - allowed automatically (safe paths)
 * - DEFAULT: Everything else requires explicit user consent
 *
 * SECURITY: Implements path traversal protection, input sanitization,
 * bash-level blacklist path enforcement, and atomic configuration loading
 * to prevent bypass attacks.
 */

import type { ExtensionAPI, ExtensionContext, SessionStartEvent } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync as fsReadFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";

// Cached home directory for consistent path expansion (no hardcoded paths)
const HOME_DIR = homedir();

/**
 * Escape a string for use as a RegExp literal.
 * Prevents special characters in file paths (e.g. dots, parens, username with +)
 * from being misinterpreted as regex metacharacters in BLACKLIST/WHITELIST entries.
 * Must be defined before BLACKLIST/WHITELIST so both can use it at module load time.
 */
function escapeRegExp(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ===== PRIORITY 1: DevOps Infrastructure Patterns =====
const dangerousBashPatterns = [
	// rm command variations - deletion flags in ANY order
	/\brm\s+(-[rRfFoOpPsuUz]*[rRfFoOpPsuUz]*)/i,                          // rm -rf, -fr, -fF
	/\brm\s+--recursive\b/i,                                               // rm --recursive
	/\brm\s+--force\b/i,                                                   // rm --force
	/\bunlink\s+/i,                                                        // unlink file
	/\brmdir\s+/i,                                                         // rmdir directory
	/\bfind\s+.*-exec\s+rm\s+/i,                                           // find ... -exec rm
	/\bfind\s+.*-exec\s+-\w+r/i,                                           // find ... -exec rm -rf
	/\bxargs\s+rm\b/i,                                                     // xargs rm (narrowed: only xargs rm, not all xargs)
	/\btruncate\s+/i,                                                      // truncate
	/\bdd\s+(if|of|bs|count|seek|skip)=/i,                                 // dd with actual disk args (narrowed: not bare `dd`)
	/\bmv\s+-f\b/i,                                                        // mv -f
	/\bchmod\s+777\b/i,                                                    // chmod 777
	/\bchmod\s+[0-7]*7[0-7]*7/i,                                          // chmod 777 variant
	/(\bcurl|\bwget)\s+.*\|.*sh\b/i,                                       // curl|sh, wget|sh
	/\bcurl.*-.*\|.*sh/i,                                                  // curl with flags pipe to sh
	/\bbash\s+-c\s+.*\brm\b/i,                                            // bash -c "rm"
	/\bbash\s+-c\s+.*rm\s+-[rRfF]/i,                                      // bash -c "rm -r"
	/\bsudo\s+.*\brm\s+-[rRfF]/i,                                         // sudo rm -rf
	/\bfind\s+.*-delete\b/i,                                              // find ... -delete
	/\brm\s+\*[rRfFoPoU]*\b/i,                                            // rm *
	/\brm\s+\*\/\*[rRfFoPoU]*\b/i,                                       // rm */*
	/\bexec\s+rm\s+/i,                                                    // exec rm
	/\bshred\s+/i,                                                        // shred (secure delete)
	/\bwipefs\s+/i,                                                       // wipefs (wipe filesystem)
	/:\s*\(\s*\)\s*\{.*:\s*\|.*:.*&.*\}/,                                 // fork bomb: :(){ :|:& };:
	/>\s*\/dev\/(sd[a-z]|nvme\d|hd[a-z])\b/i,                            // redirect to raw disk device

	// Kubernetes / kubectl
	/\bkubectl\s+delete\s+/i,                                             // kubectl delete
	/\bkubectl\s+delete\s+--all\b/i,                                      // kubectl delete --all
	/\bkubectl\s+apply\s+.*--prune/i,                                     // kubectl apply --prune
	// Helm
	/\bhelm\s+uninstall\s+/i,                                            // helm uninstall
	// Terraform / OpenTofu
	/\btofu\s+destroy\b/i,                                               // tofu destroy
	/\bterraform\s+destroy\b/i,                                          // terraform destroy
	/\btofu\s+state\s+rm\b/i,                                            // tofu state rm
	/\btofu\s+apply\s+.*-auto-app/i,                                     // tofu apply -auto-approve
	// Docker
	/\bdocker\s+rm\s+-f/i,                                               // docker rm -f
	/\bdocker\s+system\s+prune\b/i,                                      // docker system prune
	/\bdocker\s+rmi\s+-f/i,                                              // docker rmi -f
	// AWS
	/\baws\s+\w+\s+delete\b/i,                                           // aws ec2 terminate, s3 rm
	/\baws\s+s3\s+rm\s+.*--recursive/i,                                  // s3 rm --recursive (fixed: was -recursive)
	// Git
	/\bgit\s+push\s+-f/i,                                                // git push -f
	/\bgit\s+push\s+--force/i,                                           // git push --force
	/\bgit\s+reset\s+--hard\b/i,                                         // git reset --hard
	/\bgit\s+clean\s+-fd/i,                                              // git clean -fdx
	/\bgit\s+branch\s+-D/i,                                              // git branch -D
];

/**
 * Token skip list for bash command parsing.
 *
 * When tokenising a bash command to extract path arguments, these strings are
 * recognised as command/program names and skipped — they are not path candidates.
 * This is NOT a list of "commands that are checked"; ALL commands have their path
 * arguments checked. This list only prevents the command name itself from being
 * misclassified as a path argument.
 *
 * Note: "." (the POSIX source alias) is intentionally excluded. A bare "." token
 * that is an absolute/tilde/relative path is already handled by the path-shape
 * classifier below. Listing it here would cause the current-directory token "."
 * to be silently skipped rather than evaluated.
 */
const COMMAND_NAME_TOKENS = new Set([
	"cat", "bat", "less", "more", "head", "tail", "tac",  // file content
	"ls", "ll", "la", "dir", "exa", "eza", "lsd",         // directory listing
	"find", "locate", "fd",                                // file discovery
	"grep", "rg", "ag", "ack",                             // content search
	"stat", "file", "strings", "xxd", "hexdump", "od",    // file inspection
	"diff", "cmp", "comm",                                 // comparison (can leak content)
	"cp",                                                  // copy (reads source)
	"tar", "zip", "gzip", "bzip2", "xz", "zstd",          // archiving (reads source)
	"scp", "rsync",                                        // remote copy (reads source)
	"open", "xdg-open",                                    // open (reveals path)
	"nano", "vim", "vi", "nvim", "emacs", "code",          // editors
	"python", "python3", "ruby", "perl", "node",           // interpreters that may read files
	"awk", "sed", "cut", "sort", "uniq", "wc",             // text processing that reads stdin/file
	"jq", "yq", "xmllint",                                 // data query tools
	"sqlite3", "psql", "mysql",                            // DB CLI (may read credential files)
	"env", "printenv", "export",                           // environment (may reveal secrets in env)
	"source",                                              // source a file (executes it!)
	"sh", "bash", "zsh", "fish",                           // shells with file args
	"base64",                                              // encoding that reads stdin/file
	"curl", "wget",                                        // can POST file contents
	"pbcopy", "xclip", "xsel",                             // clipboard (exfiltrates content)
]);

// ===== PATH SECURITY MODEL: WHITELIST / BLACKLIST =====
// BLACKLIST has HIGHEST priority - evaluated FIRST
// WHITELIST has LOWER priority - evaluated SECOND
// Everything else → require consent (conservative default)

// Blacklisted paths (credentials/confidential data)
// escapeRegExp() is applied to HOME_DIR so usernames containing regex
// metacharacters (e.g. dots, plus signs) cannot bypass path matching.
export const BLACKLIST: RegExp[] = [
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.pi/agent/auth\\.json`),                  // Models credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.ssh/`),                                  // SSH credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.gnupg/`),                                // GPG credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/Library/Keychains/`),                       // macOS Keychain
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.aws/credentials`),                       // AWS credentials file
	new RegExp(`^${escapeRegExp(HOME_DIR)}/Pictures/Photos Library\\.photoslibrary/`), // Photos library (confidential)
	new RegExp(`^/etc/`),                                                              // System configs
	new RegExp(`^/usr/`),                                                              // System directories
	new RegExp(`^/System/`),                                                           // macOS System
];

// Whitelisted paths (safe explicit directories)
export const WHITELIST: RegExp[] = [
	new RegExp(`^${HOME_DIR}/\\.pi/$`),                                                            // Pi config directory
	new RegExp(`^/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/`),                  // Pi agent code
	// Dynamic project directory is pushed here at session_start
];

export default function (pi: ExtensionAPI) {
	let allowedPaths: string[] = [];
	let notificationsEnabled = true;
	let configLoaded = false;

	/**
	 * Validate config schema:
	 * - allowedPaths must be array of strings
	 * - notificationsEnabled must be boolean (strict type check)
	 */
	const validateConfig = (config: unknown): { valid: true; allowedPaths?: string[]; notificationsEnabled?: boolean } | { valid: false; errors: string[] } => {
		const errors: string[] = [];

		if (typeof config !== "object" || config === null || Array.isArray(config)) {
			errors.push("Config must be a plain object");
			return { valid: false, errors };
		}

		const allowedPathsRaw = (config as Record<string, unknown>)["extensions.allowedPaths"];
		if (allowedPathsRaw !== undefined) {
			if (!Array.isArray(allowedPathsRaw)) {
				errors.push("allowedPaths must be an array");
			} else {
				const invalidPaths = allowedPathsRaw.filter((p) => typeof p !== "string");
				if (invalidPaths.length > 0) {
					errors.push(`allowedPaths contains non-string values: ${JSON.stringify(invalidPaths)}`);
				}
			}
		}

		const notificationsEnabledRaw = (config as Record<string, unknown>)["extensions.notificationsEnabled"];
		if (notificationsEnabledRaw !== undefined) {
			if (typeof notificationsEnabledRaw !== "boolean") {
				errors.push(`notificationsEnabled must be boolean, got ${typeof notificationsEnabledRaw}`);
			}
		}

		if (errors.length > 0) {
			return { valid: false, errors };
		}

		return {
			valid: true,
			allowedPaths: Array.isArray(allowedPathsRaw) ? (allowedPathsRaw as string[]) : undefined,
			notificationsEnabled:
				typeof (config as Record<string, unknown>)["extensions.notificationsEnabled"] === "boolean"
					? ((config as Record<string, unknown>)["extensions.notificationsEnabled"] as boolean)
					: undefined,
		};
	};

	/**
	 * Sanitize command: Remove null bytes and zero-width characters.
	 * Prevents pattern injection attacks.
	 */
	const sanitizeCommand = (cmd: string): string => {
		return cmd
			.replace(/[\u0000-\u001F\u007F]/g, "")
			.replace(/\u200B/g, "")
			.replace(/\u200C/g, "")
			.replace(/\u200D/g, "");
	};

	/**
	 * Expand tilde to home directory using cached HOME_DIR constant.
	 * Prevents race conditions on home directory changes.
	 */
	const expandTilde = (path: string): string => {
		if (path.startsWith("~")) {
			return join(HOME_DIR, path.slice(1));
		}
		return path;
	};

	/**
	 * Check for path traversal attacks before path resolution.
	 * Matches ".." only at segment boundaries (/(../), /../, or trailing /..)
	 * to avoid false positives on filenames that legitimately contain ".." as a
	 * substring (e.g. "/home/user/..config/foo" would wrongly trigger the old
	 * path.includes("..") check).
	 */
	const hasPathTraversal = (path: string): boolean => {
		// Matches: "../", "/..", "/../", or a bare ".." token
		return /(?:^|\/)\.\.(\/|$)/.test(path);
	};

	/**
	 * Path Security Decision Engine.
	 *
	 * BLACKLIST: Highest priority - evaluated FIRST
	 * WHITELIST: Lower priority - evaluated SECOND
	 * DEFAULT: Everything else requires consent
	 */
	const checkPathSecurity = (path: string): "ALLOW" | "CONSENT_REQUIRED" | "BLOCK" => {
		if (BLACKLIST.some((p) => p.test(path))) {
			return "BLOCK";
		}
		if (WHITELIST.some((p) => p.test(path))) {
			return "ALLOW";
		}
		return "CONSENT_REQUIRED";
	};

	/**
	 * Extract candidate file/directory paths from a bash command string.
	 *
	 * Strategy: tokenise on shell boundaries, strip surrounding quotes from each
	 * token, skip command-name tokens (via COMMAND_NAME_TOKENS) and flag tokens,
	 * then classify remaining tokens by path shape:
	 *   - tilde paths  (~/... or bare ~)
	 *   - absolute paths  (/...)
	 *   - explicit relative paths  (./... or ../...)
	 *
	 * Bare words without a leading path character are intentionally skipped to
	 * avoid false positives on option values and non-path arguments. The
	 * read/write tool handler covers those cases via resolved paths.
	 *
	 * This is intentionally conservative: a false positive only triggers a
	 * consent prompt, never a silent allow.
	 */
	const extractPathsFromCommand = (command: string, cwd: string): string[] => {
		// Split on shell token boundaries (spaces, semicolons, pipes, &&, ||)
		const tokens = command
			.split(/[\s;|&]+/)
			.map((t) => t.trim())
			.filter(Boolean);

		const paths: string[] = [];

		for (let token of tokens) {
			// Strip surrounding single or double quotes so quoted paths like
			// cat "~/.ssh/config" or cat '~/.aws/credentials' are not missed.
			if (
				(token.startsWith('"') && token.endsWith('"')) ||
				(token.startsWith("'") && token.endsWith("'"))
			) {
				token = token.slice(1, -1);
			}

			// Skip flags/options
			if (token.startsWith("-")) continue;
			// Skip recognised command-name tokens (not path candidates)
			if (COMMAND_NAME_TOKENS.has(token)) continue;

			let candidate: string | null = null;

			if (token.startsWith("~/") || token === "~") {
				// Tilde path
				candidate = expandTilde(token);
			} else if (token.startsWith("/")) {
				// Absolute path
				candidate = token;
			} else if (token.startsWith("./") || token.startsWith("../")) {
				// Explicit relative path
				candidate = resolve(cwd, token);
			}
			// Bare words (e.g. "config.json" without ./) are intentionally
			// skipped to avoid false positives on command options and args.

			if (candidate) {
				// Strip any trailing shell redirects captured in the token,
				// e.g. "~/.ssh/config>" → "~/.ssh/config"
				candidate = candidate.replace(/[<>|&;].*$/, "");
				paths.push(candidate);
			}
		}

		return paths;
	};

	/**
	 * Check whether a bash command is attempting to access a blacklisted path.
	 * Returns the first offending path found, or null if safe.
	 */
	const findBlacklistedPathInCommand = (command: string, cwd: string): string | null => {
		const paths = extractPathsFromCommand(command, cwd);
		for (const p of paths) {
			if (BLACKLIST.some((bl) => bl.test(p))) {
				return p;
			}
		}
		return null;
	};

	/**
	 * Process tool call with consolidated handling for bash, read, and write.
	 *
	 * Returns a block decision synchronously (config not loaded) or via an
	 * awaited confirm dialog so the tool call is never executed before the user
	 * has answered.
	 */
	const handleToolCall = async (event: any, ctx: ExtensionContext): Promise<{ block: boolean; reason: string } | undefined> => {
		if (!configLoaded) {
			return { block: true, reason: "Configuration not fully loaded" };
		}

		if (event.toolName === "bash") {
			return handleBashTools(event.input, ctx);
		} else if (event.toolName === "read" || event.toolName === "write") {
			return handleFileIOTools(event.toolName, event.input, ctx);
		}

		return undefined;
	};

	/**
	 * Handle bash tool calls.
	 *
	 * Two-pass check:
	 *   1. Destructive pattern matching
	 *   2. Blacklisted path detection for read-like commands
	 *      (catches: ls, cat, grep, find, stat, head, tail, etc. on blacklisted dirs)
	 *
	 * In interactive mode the confirm() dialog is awaited so the tool call is
	 * suspended until the user explicitly approves or rejects. Previously the
	 * promise was fire-and-forget, allowing the tool to execute before the user
	 * responded.
	 */
	const handleBashTools = async (
		input: { command?: string },
		ctx: ExtensionContext
	): Promise<{ block: boolean; reason: string } | undefined> => {
		if (!input.command) {
			return undefined;
		}

		const command = sanitizeCommand(input.command);
		const effectiveCwd = ctx.cwd || process.cwd();

		// ── Pass 1: Destructive pattern check ────────────────────────────────────
		const isDangerous = dangerousBashPatterns.some((p) => p.test(command));
		if (isDangerous) {
			if (ctx.hasUI !== true) {
				console.log(`[safety-guard] BLOCKED bash command (non-interactive): ${command}`);
				return { block: true, reason: "Dangerous command blocked (non-interactive)" };
			}

			// Await the dialog — tool call is suspended until user responds.
			const confirmed = await ctx.ui.confirm(
				`⚠️ Dangerous bash command detected:\n\n          "${command}"\n\nConfirm execution?`,
				"This operation requires explicit confirmation."
			);
			if (!confirmed) {
				if (notificationsEnabled) ctx.ui.notify("Blocked: " + command, "warning");
				console.log(`[safety-guard] User rejected dangerous command: ${command}`);
				return { block: true, reason: "User rejected dangerous command" };
			}
			return undefined; // User approved
		}

		// ── Pass 2: Blacklisted path detection in bash command ───────────────────
		//
		// Catches read-like access to blacklisted directories via bash, e.g.:
		//   ls -la ~/.ssh/
		//   cat ~/.aws/credentials
		//   grep -r "secret" ~/.gnupg/
		//   find ~/.ssh -name "*.pub"
		//   stat /etc/passwd
		//
		const offendingPath = findBlacklistedPathInCommand(command, effectiveCwd);
		if (offendingPath !== null) {
			if (ctx.hasUI !== true) {
				// Log only the offending path (not the full command) to avoid
				// leaking sensitive content in non-interactive logs.
				console.log(
					`[safety-guard] BLOCKED bash access to blacklisted path (non-interactive): ${offendingPath}`
				);
				return {
					block: true,
					reason: `Bash command targets blacklisted path: ${offendingPath}`,
				};
			}

			// Await the dialog — tool call is suspended until user responds.
			const confirmed = await ctx.ui.confirm(
				`⚠️ Bash command targets a blacklisted path:\n\n          "${offendingPath}"\n\nThis path contains credentials or confidential data. Proceed?`,
				"Path is on blacklist for credential protection"
			);
			if (!confirmed) {
				if (notificationsEnabled) ctx.ui.notify("Blocked: access to " + offendingPath, "warning");
				console.log(`[safety-guard] User rejected bash access to blacklisted path: ${offendingPath}`);
				return { block: true, reason: `User rejected bash access to blacklisted path: ${offendingPath}` };
			}
			return undefined; // User approved
		}

		return undefined;
	};

	/**
	 * Handle file I/O tool calls (read/write) with path validation.
	 * Uses checkPathSecurity() with Blacklist priority first.
	 *
	 * All ctx.ui.confirm() calls are awaited so the tool call is suspended until
	 * the user explicitly approves or rejects (previously fire-and-forget).
	 */
	const handleFileIOTools = async (
		toolName: string,
		input: { path?: string },
		ctx: ExtensionContext
	): Promise<{ block: boolean; reason: string } | undefined> => {
		if (!input.path) {
			return undefined;
		}

		const pathParam = input.path;

		// Check path traversal before resolution
		if (hasPathTraversal(pathParam)) {
			console.log(`[safety-guard] BLOCKED path traversal attempt: ${pathParam}`);
			return { block: true, reason: "Path traversal detected" };
		}

		const effectiveCwd = ctx.cwd || process.cwd();
		const resolvedPath = resolve(effectiveCwd, pathParam);
		const securityLevel = checkPathSecurity(resolvedPath);

		// HIGHEST PRIORITY: BLACKLIST
		if (securityLevel === "BLOCK") {
			if (ctx.hasUI !== true) {
				console.log(
					`[safety-guard] BLOCKED ${toolName} on blacklisted path (non-interactive): ${resolvedPath}`
				);
				return {
					block: true,
					reason: "Blacklisted path blocked (credentials/confidential)",
				};
			}

			// Await the dialog — tool call is suspended until user responds.
			const confirmed = await ctx.ui.confirm(
				`⚠️ Blacklisted path detected (BLACKLIST priority):\n\n          "${pathParam}"\n\nThis is a blocked credentials/confidential directory. Proceed?`,
				"Path is on blacklist for credential protection"
			);
			if (!confirmed) {
				if (notificationsEnabled) ctx.ui.notify("Blocked: " + pathParam, "warning");
				console.log(`[safety-guard] User rejected blacklisted path: ${resolvedPath}`);
				return { block: true, reason: "User rejected blacklisted path" };
			}
			return undefined; // User approved
		}

		// WHITELIST: Allow automatically
		if (securityLevel === "ALLOW") {
			console.log(`[safety-guard] ALLOWED path (whitelisted): ${resolvedPath}`);
			return undefined;
		}

		// DEFAULT: Require consent
		// securityLevel === "CONSENT_REQUIRED" (exhaustive — only remaining case)
		if (ctx.hasUI !== true) {
			console.log(
				`[safety-guard] BLOCKED ${toolName} operation (non-interactive): ${pathParam}`
			);
			return {
				block: true,
				reason: "Path requires consent (not whitelisted)",
			};
		}

		// Await the dialog — tool call is suspended until user responds.
		const confirmed = await ctx.ui.confirm(
			`⚠️ Path requires consent:\n\n          "${pathParam}"\n\nConfirm execution?`,
			"Default action: require consent (not in whitelist)"
		);
		if (!confirmed) {
			if (notificationsEnabled) ctx.ui.notify("Blocked: " + pathParam, "warning");
			console.log(`[safety-guard] User rejected consent for path: ${resolvedPath}`);
			return { block: true, reason: "User rejected consent for path" };
		}
		return undefined; // User approved
	};

	/**
	 * Session start handler: Load config with validation and atomic loading.
	 */
	pi.on("session_start", (event: SessionStartEvent, ctx: ExtensionContext) => {
		let effectiveCwd = "";
		try {
			effectiveCwd = ctx.cwd || process.cwd();

			let config: Record<string, unknown> | null = null;

			// Priority 1: Project-local config
			const cwdConfigPath = join(effectiveCwd, ".pi", "settings.json");
			if (existsSync(cwdConfigPath)) {
				const content = new TextDecoder().decode(fsReadFileSync(cwdConfigPath) as Buffer);
				config = JSON.parse(content);
			}

			// Priority 2: Global agent config
			if (!config) {
				const globalConfigPath = join(dirname(effectiveCwd), "pi", "agent", "settings.json");
				if (existsSync(globalConfigPath)) {
					const content = new TextDecoder().decode(fsReadFileSync(globalConfigPath) as Buffer);
					config = JSON.parse(content);
				}
			}

			// Priority 3: Global pi config
			if (!config) {
				const globalPiConfigPath = join(dirname(effectiveCwd), "pi", "settings.json");
				if (existsSync(globalPiConfigPath)) {
					const content = new TextDecoder().decode(fsReadFileSync(globalPiConfigPath) as Buffer);
					config = JSON.parse(content);
				}
			}

			// Apply config if found and valid
			if (config) {
				const validation = validateConfig(config);
				if (!validation.valid) {
					console.error(`[safety-guard] Config validation failed: ${validation.errors.join(", ")}`);
				} else {
					// Config allowedPaths are stored separately and merged with base
					// paths below. They are NOT applied here to avoid being overwritten
					// by the base path assignment that follows.
					if (validation.allowedPaths) {
						// Expand tildes now; merging happens after base paths are set.
						allowedPaths = validation.allowedPaths.map(expandTilde);
					}
					if (validation.notificationsEnabled !== undefined) {
						notificationsEnabled = validation.notificationsEnabled;
					}
					console.log(
						`[safety-guard] Config validated: ${allowedPaths.length} user-defined paths, notifications=${notificationsEnabled}`
					);
				}
			} else {
				console.log("[safety-guard] No config found, using defaults (notify=true, allowed=~/.pi/)");
			}

			// Base whitelist paths (always included, merged with any config paths).
			// Config paths are preserved from the block above; base paths are added
			// here so user-defined entries and built-in entries both take effect.
			const basePaths = [
				expandTilde("~/.pi/"),
				expandTilde("/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/"),
			];
			// Merge: base paths first, then config paths (deduped)
			const mergedPaths = [...basePaths];
			for (const p of allowedPaths) {
				if (!mergedPaths.includes(p)) mergedPaths.push(p);
			}
			allowedPaths = mergedPaths;

			// Dynamic project directory ALWAYS added at session start
			allowedPaths.push(effectiveCwd);
			console.log(`[safety-guard] Project directory added to whitelist: ${effectiveCwd}`);

			// Rebuild WHITELIST regexes from allowedPaths so checkPathSecurity() stays in sync
			WHITELIST.length = 0;
			for (const p of allowedPaths) {
				WHITELIST.push(new RegExp(`^${escapeRegExp(p)}`));
			}

			configLoaded = true;
		} catch (error: unknown) {
			console.error("[safety-guard] Config load failed", error);
			// Safe defaults on error
			allowedPaths = [
				expandTilde("~/.pi/"),
				expandTilde("/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/"),
				effectiveCwd || process.cwd(),
			];
			notificationsEnabled = true;
			WHITELIST.length = 0;
			for (const p of allowedPaths) {
				WHITELIST.push(new RegExp(`^${escapeRegExp(p)}`));
			}
			configLoaded = true; // Prevent blocking after failed load
		}
	});

	// Register consolidated tool_call handler
	pi.on("tool_call", handleToolCall);
}
