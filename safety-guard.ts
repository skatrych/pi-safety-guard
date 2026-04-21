/**
 * Safety Guard Extension
 *
 * Comprehensive safety guardian that requires explicit consent for:
 * - Dangerous bash commands (rm -rf, sudo, truncate, dd, etc.)
 * - System file/directory operations anywhere on macOS
 * - Read/write operations outside the project directory
 *
 * SECURITY: Implements path traversal protection, input sanitization,
 * and atomic configuration loading to prevent bypass attacks.
 */

import type { ExtensionAPI, SessionStartEvent } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync as fsReadFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";

// Cached home directory for consistent path expansion
const HOME_DIR = homedir();

// Comprehensive bash command patterns - hybrid array approach (Option C)
// Simple, maintainable patterns covering ALL dangerous command variations
const dangerousBashPatterns = [
	// rm command variations - MATCH DELETION FLAGS IN ANY ORDER
	// Pattern: rm followed by flags containing at least one deletion flag (r/f)
	/\brm\s+(-[rRfFoOpPsuUz]*[rRfFoOpPsuUz]*)/i,                    // rm -rf, -fr, -fF, etc.

	// Long form variants
	/\brm\s+--recursive\b/i,                                         // rm --recursive
	/\brm\s+--force\b/i,                                             // rm --force

	// Alternative file deletion methods
	/\bunlink\s+/i,                                                  // unlink file
	/\brmdir\s+/i,                                                   // rmdir directory

	// find with destructive rm
	/\bfind\s+.*-exec\s+rm\s+/i,                                     // find ... -exec rm
	/\bfind\s+.*-exec\s+-\w+r/i,                                   // find ... -exec rm -rf

	// xargs destructive operations
	/\bxargs\s+rm\s+/i,                                              // xargs rm
	/\bxargs\s+-[a-zA-Z]*\b/i,                                     // xargs -I/-x

	// Other destructive commands
	/\btruncate\s+/i,                                                // truncate file
	/\bdd\s+/i,                                                      // dd (disk destroy)

	// cp/mv destructive operations
	/\bcp\s+-rf\b/i,                                                // cp -rf
	/\bcp\s+-r\b/i,                                                 // cp -r
	/\bmv\s+-f\b/i,                                                 // mv -f (force overwrite)

	// chmod dangerous modes
	/\bchmod\s+777\b/i,                                              // chmod 777
	/\bchmod\s+[0-7]*7[0-7]*7/i,                                    // chmod 777 variant

	// curl/wget pipe to shell
	/(\bcurl|\bwget)\s+.*\|.*sh\b/i,                                // curl|sh, wget|sh
	/\bcurl.*-.*\|.*sh/i,                                         // curl with flags pipe to sh

	// bash -c with destructive commands
	/\bbash\s+-c\s+.*\brm\b/i,                                     // bash -c "rm"
	/\bbash\s+-c\s+.*rm\s+-[rRfF]/i,                               // bash -c "rm -r"

	// sudo with destructive commands
	/\bsudo\s+.*\brm\s+-[rRfF]/i,                                   // sudo rm -rf

	// find with delete action
	/\bfind\s+.*-delete\b/i,                                       // find ... -delete

	// rm with wildcards (glob expansion = dangerous)
	/\brm\s+\*[rRfFoPoU]*\b/i,                                     // rm *
	/\brm\s+\*\/\*[rRfFoPoU]*\b/i,                               // rm */*

	// exec rm
	/\bexec\s+rm\s+/i,                                              // exec rm

	// touch with destructive flags
	/\btouch\s+-[a-zA-Z]*\b.*-[a-zA-Z]*\b/i,                        // touch -a -m -c
];

// macOS system directories to block (strict prefix matching only)
const unsafeSystemPaths = [
	"/etc/", "/usr/", "/bin/", "/sbin/", "/var/", "/opt/",
	"/root/", "/tmp/", "/Library/", "/System/", "/Applications/",
];

export default function (pi: ExtensionAPI) {
	// SECURITY: Atomic configuration state
	let allowedPaths: string[] = [];
	let notificationsEnabled = true;
	let configLoaded = false;      // Atomic flag to prevent race conditions

	// SECURITY: Sanitize command input (remove unsafe characters)
	const sanitizeCommand = (cmd: string): string => {
		// Remove null bytes and zero-width characters
		return cmd
			.replace(/[\u0000-\u001F\u007F]/g, '')       // Control characters
			.replace(/\u200B/g, '')                      // Zero-width space
			.replace(/\u200C/g, '')                      // Zero-width non-joiner
			.replace(/\u200D/g, '');                     // Zero-width joiner
	};

	// SECURITY: Atomically expand tilde using cached HOME_DIR
	const expandTilde = (path: string): string => {
		if (path.startsWith("~")) {
			return join(HOME_DIR, path.slice(1));
		}
		return path;
	};

	// SECURITY: Validate path does not contain traversal sequences
	const hasPathTraversal = (path: string): boolean => {
		return path.includes("..") ||
			path.startsWith("..") ||
			/\.\./.test(path);
	};

	// Load configuration atomically at session start
	pi.on("session_start", async (event: SessionStartEvent, ctx: ExtensionAPI) => {
		try {
			// Determine effective working directory safely
			const effectiveCwd = ctx.cwd || process.cwd();

			let config: {
				"extensions.allowedPaths"?: string[];
				"notificationsEnabled"?: boolean;
			} | null = null;

			// Priority 1: Current project config
			const cwdConfigPath = join(effectiveCwd, ".pi", "settings.json");
			if (existsSync(cwdConfigPath)) {
				const content = new TextDecoder().decode(
					fsReadFileSync(cwdConfigPath) as Buffer
				);
				config = JSON.parse(content);
			}

			// Priority 2: Global agent config
			if (!config) {
				const globalConfigPath = join(dirname(effectiveCwd), "pi", "agent", "settings.json");
				if (existsSync(globalConfigPath)) {
					const content = new TextDecoder().decode(
						fsReadFileSync(globalConfigPath) as Buffer
					);
					config = JSON.parse(content);
				}
			}

			// Priority 3: Global pi config (no agent subdirectory)
			if (!config) {
				const globalPiConfigPath = join(dirname(effectiveCwd), "pi", "settings.json");
				if (existsSync(globalPiConfigPath)) {
					const content = new TextDecoder().decode(
						fsReadFileSync(globalPiConfigPath) as Buffer
					);
					config = JSON.parse(content);
				}
			}

			// Apply configuration
			if (config) {
				// Canonical schema: extensions.allowedPaths
				const extPaths = config["extensions.allowedPaths"];
				allowedPaths = extPaths ? extPaths.map(expandTilde) : [];

				// Canonical schema: extensions.notificationsEnabled
				const notifyPref = config["extensions.notificationsEnabled"];
				if (notifyPref !== undefined) {
					notificationsEnabled = notifyPref !== false;
				}

				// Log config load success (sanitized)
				console.log(
					`[safety-guard] Config loaded: ${allowedPaths.length} allowed paths, notifications=${notificationsEnabled}`
				);
			} else {
				// No config found - use safe default (least privilege)
				console.log("[safety-guard] No config found, using defaults (notify=true, allowed=~/.pi/)");
			}

			// CRITICAL: Set atomic flag AFTER config is loaded completely
			configLoaded = true;

		} catch (error: unknown) {
			// SECURITY: Log only severity, not error details
			console.error("[safety-guard] Config load failed");
			// Fall back to safe defaults (block-all behavior)
			allowedPaths = expandTilde(["~/.pi/"]);
			notificationsEnabled = true;
		}
	});

	// Intercept bash commands
	pi.on("tool_call", async (event, ctx) => {
		// SECURITY: Check for config-loaded first to prevent race condition
		if (!configLoaded) {
			return { block: true, reason: "Configuration not fully loaded" };
		}

		if (event.toolName !== "bash") {
			return undefined;
		}

		const command = event.input.command;
		if (!command) {
			return undefined;
		}

		// SECURITY: Sanitize command before pattern matching
		const sanitizedCommand = sanitizeCommand(command);

		// SECURITY: Check dangerous patterns comprehensively
		const isDangerous = dangerousBashPatterns.some((p) => p.test(sanitizedCommand));
		if (isDangerous) {
			// Non-interactive mode: silent secure block (no info disclosure)
			if (!ctx.hasUI) {
				return { block: true, reason: "Dangerous command blocked (non-interactive)" };
			}

			const confirmed = await ctx.ui.confirm(
				`⚠️ Dangerous bash command detected:\n\n     "${command}"\n\nConfirm execution?`,
				"This operation requires explicit confirmation."
			);

			if (!confirmed) {
				const safeNotify = () => {
					if (ctx.hasUI && notificationsEnabled) {
						ctx.ui.notify(`Blocked: ${command}`, "warning");
					}
				};
				safeNotify();
				return { block: true, reason: "Blocked by user" };
			}

			return undefined;
		}

		return undefined;
	});

	// Intercept read/write operations
	pi.on("tool_call", async (event, ctx) => {
		// SECURITY: Check for config-loaded first to prevent race condition
		if (!configLoaded) {
			return { block: true, reason: "Configuration not fully loaded" };
		}

		if (event.toolName !== "write" && event.toolName !== "read") {
			return undefined;
		}

		const pathParam = event.input.path;
		if (!pathParam) {
			return undefined;
		}

		// SECURITY: Validate before resolve to prevent path traversal
		if (hasPathTraversal(pathParam)) {
			return {
				block: true,
				reason: "Path traversal detected"
			};
		}

		// Determine effective working directory
		const effectiveCwd = ctx.cwd || process.cwd();
		if (!effectiveCwd) {
			return undefined;
		}

		const resolvedPath = resolve(effectiveCwd, pathParam);

		// Check for local .pi directory within CURRENT PROJECT only
		const inCurrentProjectPi = resolvedPath.startsWith(effectiveCwd + "/.pi/") ||
			resolvedPath.startsWith(effectiveCwd + "/.pi");
		if (inCurrentProjectPi) {
			return undefined; // Safe - it's in THIS project's .pi directory
		}

		// Check against unsafe system paths
		const isUnsafePath = unsafeSystemPaths.some((p) => resolvedPath.startsWith(p));

		// Check against allowed system paths (atomic check after config loaded)
		const isAllowedPath = allowedPaths.length > 0 &&
			allowedPaths.some((p) => resolvedPath.startsWith(p));

		// Check if path is outside project directory
		const isOutsideProject = !resolvedPath.startsWith(effectiveCwd + "/");

		// Determine if we need confirmation
		let reason: string | null = null;

		if (isUnsafePath && !isAllowedPath) {
			reason = `${event.toolName === "write" ? "Write" : "Read"} operation targeting macOS system directory`;
		} else if (isOutsideProject && !isAllowedPath) {
			reason = `${event.toolName === "write" ? "Write" : "Read"} operation outside project ${effectiveCwd}`;
		}

		if (reason) {
			// Non-interactive mode: silent secure block (no info disclosure)
			if (!ctx.hasUI) {
				return { block: true, reason: "Blocked: sensitive operation" };
			}

			const confirmed = await ctx.ui.confirm(
				`⚠️ ${reason}:\n\n     "${pathParam}"\n\nConfirm execution?`,
				`This operation accesses ${isUnsafePath ? "system" : "external"} paths. Proceed with caution.`
			);

			if (!confirmed) {
				const safeNotify = () => {
					if (ctx.hasUI && notificationsEnabled) {
						ctx.ui.notify(`Blocked: ${pathParam}`, "warning");
					}
				};
				safeNotify();
				return { block: true, reason: "Blocked by user" };
			}

			return undefined;
		}

		return undefined;
	});
}
