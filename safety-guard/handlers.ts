import type { ExtensionContext, SessionStartEvent, ToolCallEvent } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync as fsReadFileSync } from "node:fs";
import { join, resolve, dirname, sep } from "node:path";
import { state } from "./state";
import { sanitizeCommand, hasPathTraversal, expandTilde } from "./utils";
import { dangerousBashPatterns, BLACKLIST, WHITELIST, escapeRegExp } from "./constants";
import { findBlacklistedPathInCommand, checkPathSecurity } from "./security";
import { validateConfig } from "./config";
import { appendSecurityPolicy } from "./prompt";
import { discoverNodeModules } from "./node-modules";

const STATIC_BLACKLIST = [...BLACKLIST];
const STATIC_WHITELIST = [...WHITELIST];

const hasNodeModulesExclusion = (command: string): boolean => {
	return /--glob\s+['"]?!node_modules\/\*\*['"]?/i.test(command)
		|| /--iglob\s+['"]?!node_modules\/\*\*['"]?/i.test(command)
		|| /-g\s+['"]?!node_modules\/\*\*['"]?/i.test(command)
		|| /-path\s+['"]?\.\/node_modules['"]?\s+-prune/i.test(command)
		|| /-not\s+-path\s+['"]?\.\/node_modules\/\*['"]?/i.test(command)
		|| /--exclude-dir(?:=|\s+)['"]?node_modules['"]?/i.test(command);
};

const isRecursiveProjectRootScan = (command: string, cwd: string): boolean => {
	const cwdEscaped = escapeRegExp(cwd);
	const findRoot = new RegExp(`\\bfind\\s+(\\.|${cwdEscaped})(?:\\s|$)`, "i");
	const grepRecursiveRoot = new RegExp(`\\bgrep\\b[^\n]*\\s-(?:[^\n]*R|R[^\n]*)\\b[^\n]*(?:\\s\\.|\\s${cwdEscaped})(?:\\s|$)`, "i");
	const rgRoot = new RegExp(`\\brg\\b[^\n]*(?:\\s\\.|\\s${cwdEscaped})(?:\\s|$)`, "i");
	return findRoot.test(command) || grepRecursiveRoot.test(command) || rgRoot.test(command);
};

const rebuildSessionBlacklist = (
	cwd: string,
	nodeModulesPaths: string[]
): void => {
	BLACKLIST.length = 0;
	BLACKLIST.push(...STATIC_BLACKLIST);

	const cwdEscaped = escapeRegExp(cwd);
	BLACKLIST.push(
		new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env$`),
		new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env\\.`),
	);

	const separator = escapeRegExp(sep);
	for (const nodeModulesPath of nodeModulesPaths) {
		BLACKLIST.push(
			new RegExp(`^${escapeRegExp(nodeModulesPath)}(?:${separator}|$)`)
		);
	}
};

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
	const effectiveCwd = resolve(ctx.cwd || process.cwd());

	// ── Pass 1: Blacklisted path detection — unconditional block ─────────────
	const offendingPath = findBlacklistedPathInCommand(command, effectiveCwd);
	if (offendingPath !== null) {
		console.log(
			`[safety-guard] BLOCKED bash access to blacklisted path: ${offendingPath}`
		);
		return {
			block: true,
			reason: `Bash command targets blacklisted path: ${offendingPath}`,
		};
	}

	// ── Pass 2: CWD-scoped recursive scans that may traverse ./node_modules ──
	if (
		state.nodeModulesInCwdTree &&
		isRecursiveProjectRootScan(command, effectiveCwd) &&
		!hasNodeModulesExclusion(command)
	) {
		console.log(`[safety-guard] BLOCKED recursive project-root scan without node_modules exclusion: ${command}`);
		return {
			block: true,
			reason: "Recursive project scan requires explicit node_modules exclusion",
		};
	}

	// ── Pass 3: Destructive pattern check ────────────────────────────────────
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

	return undefined;
};

/**
 * Handle file I/O tool calls (read/write/edit) with path validation.
 */
export const handleFileIOTools = async (
	toolName: "read" | "write" | "edit",
	input: unknown,
	ctx: ExtensionContext
): Promise<{ block: boolean; reason: string } | undefined> => {
	if (!input || typeof input !== "object") {
		return undefined;
	}

	const pathParam = (input as { path?: unknown }).path;
	if (typeof pathParam !== "string" || pathParam.length === 0) {
		return undefined;
	}

	// Check path traversal before resolution
	if (hasPathTraversal(pathParam)) {
		console.log(`[safety-guard] BLOCKED path traversal attempt: ${pathParam}`);
		return { block: true, reason: "Path traversal detected" };
	}

	const effectiveCwd = ctx.cwd || process.cwd();
	const expandedPathParam = expandTilde(pathParam);
	const resolvedPath = resolve(effectiveCwd, expandedPathParam);
	const securityLevel = checkPathSecurity(resolvedPath);

	// HIGHEST PRIORITY: BLACKLIST — strict block, no user override
	if (securityLevel === "BLOCK") {
		console.log(
			`[safety-guard] BLOCKED ${toolName} on blacklisted path: ${resolvedPath}`
		);
		return {
			block: true,
			reason: "Blacklisted path blocked (credentials/confidential)",
		};
	}

	// WHITELIST: Allow automatically
	if (securityLevel === "ALLOW") {
		console.log(`[safety-guard] ALLOWED path (whitelisted): ${resolvedPath}`);
		return undefined;
	}

	// FALLBACK: Allow any path under the current project directory.
	// Guards against the case where ctx.cwd was not yet available at session_start,
	// causing the whitelist to be built with process.cwd() instead of the project dir.
	const cwdNormalized = effectiveCwd.endsWith("/") ? effectiveCwd : effectiveCwd + "/";
	if (resolvedPath.startsWith(cwdNormalized)) {
		console.log(`[safety-guard] ALLOWED path (project directory): ${resolvedPath}`);
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
	} else if (event.toolName === "read" || event.toolName === "write" || event.toolName === "edit") {
		return handleFileIOTools(event.toolName, event.input, ctx);
	}

	return undefined;
};

/**
 * Session start handler: Load config and set up whitelist/blacklist.
 */
export const onSessionStart = (event: SessionStartEvent, ctx: ExtensionContext) => {
	const effectiveCwd = resolve(ctx.cwd || process.cwd());
	const nodeModulesDiscovery = discoverNodeModules(effectiveCwd);

	state.nodeModulesPaths = nodeModulesDiscovery.paths;
	state.nodeModulesInCwdTree = nodeModulesDiscovery.nodeModulesInCwdTree;

	console.log(
		`[safety-guard] node_modules locations=${nodeModulesDiscovery.paths.length}, ` +
		`inCwdTree=${nodeModulesDiscovery.nodeModulesInCwdTree}`
	);

	try {
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
			console.log("[safety-guard] No config found, using defaults (notify=true, global whitelist preserved)");
		}

		// Session/project-specific whitelist paths from config.
		const mergedPaths = [...state.allowedPaths];

		// Dynamic project directory
		if (!mergedPaths.includes(effectiveCwd)) mergedPaths.push(effectiveCwd);
		state.allowedPaths = mergedPaths;
		console.log(`[safety-guard] Project directory added to whitelist: ${effectiveCwd}`);

		// Rebuild session/project-specific whitelist regexes, preserving global defaults.
		WHITELIST.length = 0;
		WHITELIST.push(...STATIC_WHITELIST);
		for (const p of state.allowedPaths) {
			WHITELIST.push(new RegExp(`^${escapeRegExp(p)}`));
		}

		rebuildSessionBlacklist(effectiveCwd, nodeModulesDiscovery.paths);
		console.log(`[safety-guard] Project blacklist entries added (.env at all depths, node_modules): ${effectiveCwd}, security policy appended to system prompt`);

		state.configLoaded = true;
	} catch (error: unknown) {
		console.error("[safety-guard] Config load failed", error);
		const fallbackCwd = effectiveCwd || process.cwd();
		state.allowedPaths = [fallbackCwd];
		state.notificationsEnabled = true;
		WHITELIST.length = 0;
		WHITELIST.push(...STATIC_WHITELIST);
		for (const p of state.allowedPaths) {
			WHITELIST.push(new RegExp(`^${escapeRegExp(p)}`));
		}
		rebuildSessionBlacklist(fallbackCwd, nodeModulesDiscovery.paths);
		state.configLoaded = true;
	}
};
