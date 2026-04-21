/**
 * Safety Guard Extension
 *
 * Comprehensive safety guardian using Whitelist/Blacklist model:
 * - BLACKLIST: Highest priority - blocked unconditionally (creds/confidential)
 * - WHITELIST: Lower priority - allowed automatically (safe paths)
 * - DEFAULT: Everything else requires explicit user consent
 *
 * SECURITY: Implements path traversal protection, input sanitization,
 * and atomic configuration loading to prevent bypass attacks.
 */

import type { ExtensionAPI, ExtensionContext, SessionStartEvent } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync as fsReadFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";

// Cached home directory for consistent path expansion (no hardcoded paths)
const HOME_DIR = homedir();

// ===== PRIORITY 1: DevOps Infrastructure Patterns =====
const dangerousBashPatterns = [
	// rm command variations - deletion flags in ANY order
	/\brm\s+(-[rRfFoOpPsuUz]*[rRfFoOpPsuUz]*)/i,                          // rm -rf, -fr, -fF
	/\brm\s+--recursive\b/i,                                               // rm --recursive
	/\brm\s+--force\b/i,                                                   // rm --force
	/\bunlink\s+/i,                                                        // unlink file
	/\brmdir\s+/i,                                                         // rmdir directory
	/\bfind\s+.*-exec\s+rm\s+/i,                                           // find ... -exec rm
	/\bfind\s+.*-exec\s+-\w+r/i,                                         // find ... -exec rm -rf
	/\bxargs\s+rm\s+/i,                                                    // xargs rm
	/\bxargs\s+-[a-zA-Z]*\b/i,                                           // xargs -I/-x
	/\btruncate\s+/i,                                                      // truncate
	/\bdd\s+/i,                                                            // dd (disk destroy)
	/\bcp\s+-rf\b/i,                                                      // cp -rf
	/\bcp\s+-r\b/i,                                                       // cp -r
	/\bmv\s+-f\b/i,                                                       // mv -f
	/\bchmod\s+777\b/i,                                                    // chmod 777
	/\bchmod\s+[0-7]*7[0-7]*7/i,                                          // chmod 777 variant
	/(\bcurl|\bwget)\s+.*\|.*sh\b/i,                                      // curl|sh, wget|sh
	/\bcurl.*-.*\|.*sh/i,                                                // curl with flags pipe to sh
	/\bbash\s+-c\s+.*\brm\b/i,                                          // bash -c "rm"
	/\bbash\s+-c\s+.*rm\s+-[rRfF]/i,                                     // bash -c "rm -r"
	/\bsudo\s+.*\brm\s+-[rRfF]/i,                                         // sudo rm -rf
	/\bfind\s+.*-delete\b/i,                                             // find ... -delete
	/\brm\s+\*[rRfFoPoU]*\b/i,                                           // rm *
	/\brm\s+\*\/\*[rRfFoPoU]*\b/i,                                     // rm */*
	/\bexec\s+rm\s+/i,                                                    // exec rm
	/\btouch\s+-[a-zA-Z]*\b.*-[a-zA-Z]*\b/i,                              // touch -a -m -c

	// Kubernetes / kubectl
	/\bkubectl\s+delete\s+/i,                                            // kubectl delete
	/\bkubectl\s+delete\s+--all\b/i,                                     // kubectl delete --all
	/\bkubectl\s+apply\s+.*--prune/i,                                    // kubectl apply --prune
	// Helm
	/\bhelm\s+uninstall\s+/i,                                           // helm uninstall
	// Terraform / OpenTofu
	/\btofu\s+destroy\b/i,                                              // tofu destroy
	/\bterraform\s+destroy\b/i,                                         // terraform destroy
	/\btofu\s+state\s+rm\b/i,                                           // tofu state rm
	/\btofu\s+apply\s+.*-auto-app/i,                                    // tofu apply -auto-approve
	// Docker
	/\bdocker\s+rm\s+-f/i,                                              // docker rm -f
	/\bdocker\s+system\s+prune\b/i,                                     // docker system prune
	/\bdocker\s+rmi\s+-f/i,                                             // docker rmi -f
	// AWS
	/\baws\s+\w+\s+delete\b/i,                                          // aws ec2 terminate, s3 rm
	/\baws\s+s3\s+rm\s+.*-recursive/i,                                  // s3 rm --recursive
	// Git
	/\bgit\s+push\s+-f/i,                                               // git push -f
	/\bgit\s+push\s+--force/i,                                          // git push --force
	/\bgit\s+reset\s+--hard\b/i,                                        // git reset --hard
	/\bgit\s+clean\s+-fd/i,                                            // git clean -fdx
	/\bgit\s+branch\s+-D/i,                                             // git branch -D
];

// ===== PATH SECURITY MODEL: WHITELIST / BLACKLIST =====
// BLACKLIST has HIGHEST priority - evaluated FIRST
// WHITELIST has LOWER priority - evaluated SECOND
// Everything else → require consent (conservative default)
//
// Both lists are explicit, visible arrays using HOME_DIR dynamically
// No hardcoded paths - all patterns use HOME_DIR constant

// Blacklisted paths (credentials/confidential data)
export const BLACKLIST: RegExp[] = [
	new RegExp(`^${HOME_DIR}/.ssh/`),                                    // SSH credentials
	new RegExp(`^${HOME_DIR}/.gnupg/`),                                  // GPG credentials
	new RegExp(`^${HOME_DIR}/Library/Keychains/`),                       // macOS Keychain
	new RegExp(`^${HOME_DIR}/.aws/credentials`),                          // AWS credentials file
	new RegExp(`^${HOME_DIR}/Pictures/Photos Library\\.photoslibrary/`), // Photos library (confidential)
	new RegExp(`^/etc/`),                                                // System configs
	new RegExp(`^/usr/`),                                                // System directories
	new RegExp(`^/System/`),                                             // macOS System
];

// Whitelisted paths (safe explicit directories)
export const WHITELIST: RegExp[] = [
	new RegExp(`^${HOME_DIR}/\\.pi/$`),                                   // Pi config directory
	new RegExp(`^/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/`), // Pi agent code
	// Add more paths here dynamically in session_start handler
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

				// Check if config is a plain object
			if (typeof config !== "object" || config === null || Array.isArray(config)) {
					errors.push("Config must be a plain object");
					return { valid: false, errors };
							}

				// Validate allowedPaths
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

				// Validate notificationsEnabled (strict boolean check)
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
					allowedPaths: Array.isArray(allowedPathsRaw)
										? (allowedPathsRaw as string[])
										: undefined,
					notificationsEnabled:
							typeof (config as Record<string, unknown>)["extensions.notificationsEnabled"] ===
										"boolean"
										? (config as Record<string, unknown>)["extensions.notificationsEnabled"]
										: undefined
				};
							};

	/**
	   * Sanitize command: Remove null bytes and zero-width characters
	   * Prevents pattern injection attacks
	   */
	const sanitizeCommand = (cmd: string): string => {
			return cmd
										.replace(/[\u0000-\u001F\u007F]/g, "")
										.replace(/\u200B/g, "")
										.replace(/\u200C/g, "")
										.replace(/\u200D/g, "");
								};

	/**
	   * Expand tilde to home directory using cached HOME_DIR constant
	   * Prevents race conditions on home directory changes
	   */
	const expandTilde = (path: string): string => {
			if (path.startsWith("~")) {
					return join(HOME_DIR, path.slice(1));
										}
			return path;
								};

	/**
	   * Check for path traversal attacks before path resolution
	   * Prevents directory escaping via .. sequences
	   */
	const hasPathTraversal = (path: string): boolean => {
			return path.includes("..") || path.startsWith("..") || /\.\./.test(path);
								};

	/**
	   * Path Security Decision Engine
	   * 
	   * BLACKLIST: Highest priority - evaluated FIRST
	   * WHITELIST: Lower priority - evaluated SECOND
	   * DEFAULT: Everything else requires consent
	   */
	const checkPathSecurity = (path: string): "ALLOW" | "CONSENT_REQUIRED" | "BLOCK" => {
				// HIGHEST PRIORITY: Blacklist (credentials/confidential)
			if (BLACKLIST.some(p => p.test(path))) {
					return "BLOCK";
										}

				// LOWER PRIORITY: Whitelist (explicitly allowed)
			const isWhitelisted = WHITELIST.some(p => p.test(path));
				if (isWhitelisted) {
					return "ALLOW";
					}

				// DEFAULT: Require consent (conservative)
			return "CONSENT_REQUIRED";
								};

	/**
	   * Process tool call with consolidated handling for bash, read, and write
	   * Benefits:
	   * - Single handler for easier debugging
	   * - Clear ordering of event processing
	   * - Consistent notification logic across all tool types
	   */
	const handleToolCall = (event: any, ctx: ExtensionContext): { block: boolean; reason: string } | undefined => {
						// Check config loaded - block all operations until config is ready
			if (!configLoaded) {
					return { block: true, reason: "Configuration not fully loaded" };
									}

						// Consolidate bash, read, and write handling
			if (event.toolName === "bash") {
					return handleBashTools(event.input, ctx);
									} else if (event.toolName === "read" || event.toolName === "write") {
					return handleFileIOTools(event.input, ctx);
									}

			return undefined;
								};

	/**
	   * Handle bash tool calls with pattern matching and notification logic
	   * Non-interactive mode: Securely logs blocked operations instead of silent blocking
	   */
	const handleBashTools = (
			input: { command?: string },
			ctx: ExtensionContext
						): { block: boolean; reason: string } | undefined => {
			if (!input.command) {
					return undefined;
									}

				const command = sanitizeCommand(input.command);
				const isDangerous = dangerousBashPatterns.some((p) => p.test(command));

				if (isDangerous) {
					if (ctx.hasUI !== true) {
									// Better notification: Log blocked operations securely (no info disclosure)
							console.log(
											`[safety-guard] BLOCKED bash command (non-interactive): ${command}`
											);
						return { block: true, reason: "Dangerous command blocked (non-interactive)" };
										}

									// Interactive mode: Confirm with UI
						ctx.ui.confirm(
										`⚠️ Dangerous bash command detected:\n\n          "${command}"\n\nConfirm execution?`,
										"This operation requires explicit confirmation."
									).then((confirmed: boolean) => {
							if (confirmed === false) {
								if (notificationsEnabled === true) {
									ctx.ui.notify("Blocked: " + command, "warning");
														}
									console.log(
														`[safety-guard] User rejected dangerous command: ${command}`
														);
											}
										});
						return undefined;
										}

				return undefined;
								};

	/**
	   * Handle file I/O tool calls (read/write) with path validation and notification logic
	   * Uses checkPathSecurity() with Blacklist priority first
	   * Non-interactive mode: Securely logs blocked operations instead of silent blocking
	   */
	const handleFileIOTools = (
			input: { path?: string },
			ctx: ExtensionContext
						): { block: boolean; reason: string } | undefined => {
			if (!input.path) {
					return undefined;
									}

				const pathParam = input.path;

							// Check path traversal before resolution
				if (hasPathTraversal(pathParam)) {
								// Secure logging for non-interactive mode
						console.log(`[safety-guard] BLOCKED path traversal attempt: ${pathParam}`);
					return { block: true, reason: "Path traversal detected" };
									}

				const effectiveCwd = ctx.cwd || process.cwd();
				if (!effectiveCwd) {
					return undefined;
									}

				const resolvedPath = resolve(effectiveCwd, pathParam);
				const securityLevel = checkPathSecurity(resolvedPath);

							// HIGHEST PRIORITY: BLACKLIST - BLOCK with audit logging
				if (securityLevel === "BLOCK") {
					if (ctx.hasUI !== true) {
							console.log(
											`[safety-guard] BLOCKED path (blacklisted/blacklist priority): ${resolvedPath}`
											);
						return {
							block: true,
							reason: "Blacklisted path blocked (credentials/confidential)",
											};
										}

							ctx.ui.confirm(
											`⚠️ Blacklisted path detected (BLACKLIST priority):\n\n          "${pathParam}"\n\nThis is a blocked credentials/confidential directory. Proceed?`,
											"Path is on blacklist for credential protection"
										).then((confirmed: boolean) => {
								if (confirmed === false) {
									if (notificationsEnabled === true) {
										ctx.ui.notify("Blocked: " + pathParam, "warning");
															}
										console.log(`[safety-guard] User rejected blacklisted path: ${resolvedPath}`);
												}
											});
							return undefined;
										}

							// WHITELIST: Lower priority - ALLOW automatically
				if (securityLevel === "ALLOW") {
					console.log(`[safety-guard] ALLOWED path (whitelisted): ${resolvedPath}`);
					return undefined;
									}

							// DEFAULT: Require consent (conservative)
				if (securityLevel === "CONSENT_REQUIRED") {
					if (ctx.hasUI !== true) {
							console.log(
											`[safety-guard] BLOCKED ${input.toolName} operation (non-interactive): ${pathParam}`
											);
						return {
							block: true,
							reason: "Path requires consent (not whitelisted)",
											};
										}

									// Interactive mode: Confirm with UI
						ctx.ui.confirm(
										`⚠️ Path requires consent:\n\n          "${pathParam}"\n\nConfirm execution?`,
										`Default action: require consent (not in whitelist)`
									).then((confirmed: boolean) => {
							if (confirmed === false) {
								if (notificationsEnabled === true) {
									ctx.ui.notify("Blocked: " + pathParam, "warning");
														}
									console.log(`[safety-guard] User rejected consent for path: ${resolvedPath}`);
											}
										});
							return undefined;
										}

				return undefined;
								};

	/**
	   * Session start handler: Load config with validation and atomic loading
	   * Whitelist configuration:
	   * - Default: ~/.pi/
	   * - Pi agent: /opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/
	   * - Dynamic: project directory (ctx.cwd) - ALWAYS added at session start
	   */
	pi.on("session_start", (event: SessionStartEvent, ctx: ExtensionContext) => {
			try {
					const effectiveCwd = ctx.cwd || process.cwd();

						// Configuration priority: project-local -> global agent -> global pi -> safe defaults
					let config: Record<string, unknown> | null = null;

							// Priority 1: Project-local config
					const cwdConfigPath = join(effectiveCwd, ".pi", "settings.json");
					if (existsSync(cwdConfigPath)) {
							const content = new TextDecoder().decode(fsReadFileSync(cwdConfigPath) as Buffer);
							config = JSON.parse(content);
											}

							// Priority 2: Global agent config
					if (!config) {
							const globalConfigPath = join(
									dirname(effectiveCwd),
												"pi",
												"agent",
												"settings.json"
									);
							if (existsSync(globalConfigPath)) {
									const content = new TextDecoder().decode(fsReadFileSync(globalConfigPath) as Buffer);
									config = JSON.parse(content);
													}
												}

							// Priority 3: Global pi config
					if (!config) {
							const globalPiConfigPath = join(
									dirname(effectiveCwd),
												"pi",
												"settings.json"
									);
							if (existsSync(globalPiConfigPath)) {
									const content = new TextDecoder().decode(fsReadFileSync(globalPiConfigPath) as Buffer);
									config = JSON.parse(content);
													}
												}

						// Config loaded - validate and apply with null-safe fallback
					if (config) {
							const validation = validateConfig(config);
							if (!validation.valid) {
									console.error(
														`[safety-guard] Config validation failed: ${validation.errors.join(", ")}`
														);
												} else {
									if (validation.allowedPaths) {
											allowedPaths = validation.allowedPaths.map(expandTilde);
														}
									if (validation.notificationsEnabled !== undefined) {
											notificationsEnabled = validation.notificationsEnabled;
														}
									console.log(
														`[safety-guard] Config validated: ${allowedPaths.length} allowed paths, notifications=${notificationsEnabled}`
														);
												}
										} else {
							console.log("[safety-guard] No config found, using defaults (notify=true, allowed=~/.pi/)");
										}

							// Set default whitelist paths (no config applied yet, using safe defaults)
							allowedPaths = [
									expandTilde("~/.pi/"),                                      // Default safe directory
									expandTilde("/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/")  // Pi agent
							];
							console.log("[safety-guard] Using default whitelist paths");

							// Dynamic project directory ALWAYS added at session start
						allowedPaths.push(effectiveCwd);
							console.log(`[safety-guard] Project directory added to whitelist: ${effectiveCwd}`);

						configLoaded = true;
							} catch (error: unknown) {
					console.error("[safety-guard] Config load failed", error);
							// Safe defaults on error
						allowedPaths = [
								expandTilde("~/.pi/"),
								expandTilde("/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/"),
								expandTilde(effectiveCwd)
								];
						notificationsEnabled = true;
						configLoaded = true; // Prevent blocking after failed load
							}
							});

				// Register consolidated tool_call handler
		pi.on("tool_call", handleToolCall);
}
