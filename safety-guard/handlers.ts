import type { ExtensionContext, SessionStartEvent, ToolCallEvent } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync as fsReadFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { state } from "./state";
import { sanitizeCommand, hasPathTraversal, expandTilde } from "./utils";
import { dangerousBashPatterns, BLACKLIST, WHITELIST, escapeRegExp } from "./constants";
import { findBlacklistedPathInCommand, checkPathSecurity } from "./security";
import { validateConfig } from "./config";
import { appendSecurityPolicy } from "./prompt";

/**
 * Handle bash tool calls.
 */
export const handleBashTools = async (
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
			if (state.notificationsEnabled) ctx.ui.notify("Blocked: " + command, "warning");
			console.log(`[safety-guard] User rejected dangerous command: ${command}`);
			return { block: true, reason: "User rejected dangerous command" };
		}
		return undefined; // User approved
	}

	// ── Pass 2: Blacklisted path detection in bash command ───────────────────
	const offendingPath = findBlacklistedPathInCommand(command, effectiveCwd);
	if (offendingPath !== null) {
		if (ctx.hasUI !== true) {
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
			if (state.notificationsEnabled) ctx.ui.notify("Blocked: access to " + offendingPath, "warning");
			console.log(`[safety-guard] User rejected bash access to blacklisted path: ${offendingPath}`);
			return { block: true, reason: `User rejected bash access to blacklisted path: ${offendingPath}` };
		}
		return undefined; // User approved
	}

	return undefined;
};

/**
 * Handle file I/O tool calls (read/write) with path validation.
 */
export const handleFileIOTools = async (
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
			if (state.notificationsEnabled) ctx.ui.notify("Blocked: " + pathParam, "warning");
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
		if (state.notificationsEnabled) ctx.ui.notify("Blocked: " + pathParam, "warning");
		console.log(`[safety-guard] User rejected consent for path: ${resolvedPath}`);
		return { block: true, reason: "User rejected consent for path" };
	}
	return undefined; // User approved
};

/**
 * Main tool call dispatcher.
 */
export const handleToolCall = async (event: ToolCallEvent, ctx: ExtensionContext): Promise<{ block: boolean; reason: string } | undefined> => {
	if (!state.configLoaded) {
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
 * Session start handler: Load config and set up whitelist/blacklist.
 */
export const onSessionStart = (event: SessionStartEvent, ctx: ExtensionContext) => {
	let effectiveCwd = "";
	try {
		effectiveCwd = ctx.cwd || process.cwd();
		// Append security policy to system prompt
		if (ctx.systemPrompt) {
			ctx.systemPrompt = appendSecurityPolicy(ctx.systemPrompt);
		}
		if (ctx.aiSystemMessage) {
			ctx.aiSystemMessage = appendSecurityPolicy(ctx.aiSystemMessage);
		}

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
				if (validation.allowedPaths) {
					state.allowedPaths = validation.allowedPaths.map(expandTilde);
				}
				if (validation.notificationsEnabled !== undefined) {
					state.notificationsEnabled = validation.notificationsEnabled;
				}
				console.log(
					`[safety-guard] Config validated: ${state.allowedPaths.length} user-defined paths, notifications=${state.notificationsEnabled}`
				);
			}
		} else {
			console.log("[safety-guard] No config found, using defaults (notify=true, allowed=~/.pi/)");
		}

		// Base whitelist paths
		const basePaths = [
			expandTilde("~/.pi/"),
			expandTilde("/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/"),
		];
		
		// Merge: base paths first, then config paths (deduped)
		const mergedPaths = [...basePaths];
		for (const p of state.allowedPaths) {
			if (!mergedPaths.includes(p)) mergedPaths.push(p);
		}
		state.allowedPaths = mergedPaths;

		// Dynamic project directory
		state.allowedPaths.push(effectiveCwd);
		console.log(`[safety-guard] Project directory added to whitelist: ${effectiveCwd}`);

		// Rebuild WHITELIST regexes
		WHITELIST.length = 0;
		for (const p of state.allowedPaths) {
			WHITELIST.push(new RegExp(`^${escapeRegExp(p)}`));
		}

		// Blacklist project-specific .env files
		const cwdEscaped = escapeRegExp(effectiveCwd);
		BLACKLIST.push(
			new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env$`),
			new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env\\.`),
		);
		console.log(`[safety-guard] .env blacklist entries added for project directory (all depths): ${effectiveCwd}, security policy appended to system prompt`);

		state.configLoaded = true;
	} catch (error: unknown) {
		console.error("[safety-guard] Config load failed", error);
		const fallbackCwd = effectiveCwd || process.cwd();
		state.allowedPaths = [
			expandTilde("~/.pi/"),
			expandTilde("/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/"),
			fallbackCwd,
		];
		state.notificationsEnabled = true;
		WHITELIST.length = 0;
		for (const p of state.allowedPaths) {
			WHITELIST.push(new RegExp(`^${escapeRegExp(p)}`));
		}
		const cwdEscaped = escapeRegExp(fallbackCwd);
		BLACKLIST.push(
			new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env$`),
			new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env\\.`),
		);
		state.configLoaded = true;
	}
};
