import type { ExtensionContext, SessionStartEvent, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync as fsReadFileSync } from "node:fs";
import { join, resolve, dirname, sep, relative } from "node:path";
import { state } from "./state";
import { sanitizeCommand, hasPathTraversal, expandTilde } from "./utils";
import {
	dangerousBashPatterns,
	projectLocalDeletionPatterns,
	BLACKLIST,
	WHITELIST,
	escapeRegExp,
	compileBlockedPaths,
} from "./constants";
import {
	checkPathSecurity,
	extractDestructivePathsFromCommand,
	extractPathsFromCommand,
} from "./security";
import { validateConfig, loadGlobalPermissionGatesEnabled, loadGlobalBlockedPaths } from "./config";
import { appendSecurityPolicy } from "./prompt";
import { discoverNodeModules } from "./node-modules";

const STATIC_WHITELIST = [...WHITELIST];

const stripTrailingSep = (path: string): string => {
	if (path.length > 1 && path.endsWith(sep)) {
		return path.slice(0, -1);
	}
	return path;
};

const resolveCommandPathToken = (token: string, cwd: string): string => {
	const cleaned = token.replace(/^['"]|['"]$/g, "");
	if (cleaned.startsWith("~/") || cleaned === "~") {
		return stripTrailingSep(expandTilde(cleaned));
	}
	if (cleaned.startsWith("/")) {
		return stripTrailingSep(cleaned);
	}
	return stripTrailingSep(resolve(cwd, cleaned));
};

const discoveredRootSet = (): Set<string> => {
	return new Set(state.nodeModulesPaths.map(stripTrailingSep));
};

/**
 * Discovered node_modules roots referenced as `-path <root> -prune` operands.
 * Used for Pass 1 carve-out (only prune operands) and Pass 2 exclusion detection.
 */
const prunedDiscoveredRoots = (command: string, cwd: string): Set<string> => {
	const roots = discoveredRootSet();
	const found = new Set<string>();
	const re = /-path\s+(['"]?)([^\s'"]+)\1\s+-prune/gi;
	let match: RegExpExecArray | null;
	while ((match = re.exec(command)) !== null) {
		const resolved = resolveCommandPathToken(match[2], cwd);
		if (roots.has(resolved)) {
			found.add(resolved);
		}
	}
	return found;
};

const hasNotPathExclusionForDiscoveredRoots = (command: string, cwd: string): boolean => {
	for (const root of state.nodeModulesPaths) {
		const normRoot = stripTrailingSep(root);
		const rel = relative(cwd, normRoot);
		const tokens = [`${normRoot}/*`];
		if (rel && !rel.startsWith("..") && !rel.startsWith(sep)) {
			tokens.push(`${rel}/*`, `./${rel}/*`);
		}
		for (const token of tokens) {
			const escaped = escapeRegExp(token);
			if (new RegExp(`-not\\s+-path\\s+['"]?${escaped}['"]?`, "i").test(command)) {
				return true;
			}
		}
	}
	return false;
};

/**
 * True when the command has an accepted find exclusion for a discovered node_modules root.
 * Content-search flags (rg --glob, grep --exclude-dir) are ignored: Pass 2 gates find only,
 * and those flags do not make find skip node_modules.
 */
const hasNodeModulesExclusion = (command: string, cwd: string): boolean => {
	if (prunedDiscoveredRoots(command, cwd).size > 0) {
		return true;
	}
	return hasNotPathExclusionForDiscoveredRoots(command, cwd);
};

/** Pass 2: project-root `find` only (rg/grep are not gated). */
const isProjectRootFind = (command: string, cwd: string): boolean => {
	const cwdEscaped = escapeRegExp(stripTrailingSep(cwd));
	// `.`, `./`, absolute cwd, and absolute cwd with trailing separator
	return new RegExp(`\\bfind\\s+(\\.\\/?|${cwdEscaped}\\/?)(?:\\s|$)`, "i").test(command);
};

const rebuildSessionBlacklist = (
	cwd: string,
	nodeModulesPaths: string[]
): void => {
	BLACKLIST.length = 0;
	state.blockedPaths = state.blockedPaths.map((path) => resolve(cwd, expandTilde(path)));
	state.blockedPathPatterns = compileBlockedPaths(state.blockedPaths, cwd);
	BLACKLIST.push(...state.blockedPathPatterns);

	const cwdEscaped = escapeRegExp(cwd);
	BLACKLIST.push(
		new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env$`),
		new RegExp(`^${cwdEscaped}/(?:.+/)?\\.env\\.`),
	);

	const separator = escapeRegExp(sep);
	for (const nodeModulesPath of nodeModulesPaths) {
		// Exact root only: bash/read may target specific packages under node_modules.
		BLACKLIST.push(
			new RegExp(`^${escapeRegExp(nodeModulesPath)}(?:${separator})?$`)
		);
	}
};

const isUnderDiscoveredNodeModules = (resolvedPath: string): boolean => {
	for (const nodeModulesPath of state.nodeModulesPaths) {
		if (
			resolvedPath === nodeModulesPath ||
			resolvedPath.startsWith(nodeModulesPath + sep)
		) {
			return true;
		}
	}
	return false;
};

/**
 * Pass 1: first blacklisted path in the command.
 * Exact discovered node_modules roots may be prune operands or safe local deletion
 * targets. Neither exception overrides an explicitly configured blocked path.
 */
const findPass1OffendingPath = (command: string, cwd: string, allowProjectDeletion: boolean): string | null => {
	const prunedRoots = prunedDiscoveredRoots(command, cwd);
	const roots = discoveredRootSet();
	const paths = [...extractPathsFromCommand(command, cwd), ...extractDestructivePathsFromCommand(command, cwd)];
	for (const path of paths) {
		if (!BLACKLIST.some((bl) => bl.test(path))) {
			continue;
		}
		if (
			!state.blockedPathPatterns.some((pattern) => pattern.test(path)) &&
			(prunedRoots.has(stripTrailingSep(path)) || (allowProjectDeletion && roots.has(stripTrailingSep(path))))
		) {
			continue;
		}
		return path;
	}
	return null;
};

/**
 * Allow direct deletion commands when every known target is a project descendant.
 * Sensitive paths remain protected, including project .env files. Unknown shell
 * expansions and hidden-file globs are kept on the normal confirmation path.
 */
const isProjectLocalDeletion = (command: string, cwd: string): boolean => {
	if (!projectLocalDeletionPatterns.some((pattern) => pattern.test(command))) {
		return false;
	}
	if (command.includes("$") || command.includes("`")) {
		return false;
	}
	if (/(^|[\s/])\.[^/\s]*\*/.test(command)) {
		return false;
	}
	if (
		dangerousBashPatterns.some(
			(pattern) => !projectLocalDeletionPatterns.includes(pattern) && pattern.test(command)
		)
	) {
		return false;
	}

	const targets = extractDestructivePathsFromCommand(command, cwd);
	const projectPrefix = cwd.endsWith(sep) ? cwd : cwd + sep;
	if (targets.length === 0) return false;

	const projectEnv = new RegExp(`^${escapeRegExp(cwd)}/(?:.+/)?\\.env(?:$|\\.)`);
	return targets.every((target) => {
		if (!target.startsWith(projectPrefix) || target === cwd) return false;
		if (projectEnv.test(target)) return false;
		return !state.blockedPathPatterns.some((pattern) => pattern.test(target));
	});
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
	const allowProjectDeletion = isProjectLocalDeletion(command, effectiveCwd);

	// ── Pass 1: Blacklisted path detection — unconditional block ─────────────
	// Exceptions: exact discovered node_modules roots used as prune operands, or
	// as targets of an otherwise safe project-local deletion.
	const offendingPath = findPass1OffendingPath(command, effectiveCwd, allowProjectDeletion);
	if (offendingPath !== null) {
		console.log(
			`[safety-guard] BLOCKED bash access to blacklisted path: ${offendingPath}`
		);
		return {
			block: true,
			reason: `Bash command targets blacklisted path: ${offendingPath}`,
		};
	}

	// ── Pass 2: CWD-scoped project-root find that may traverse ./node_modules ─
	if (
		state.nodeModulesInCwdTree &&
		isProjectRootFind(command, effectiveCwd) &&
		!hasNodeModulesExclusion(command, effectiveCwd)
	) {
		console.log(`[safety-guard] BLOCKED project-root find without node_modules exclusion: ${command}`);
		return {
			block: true,
			reason: "Project-root find requires explicit node_modules exclusion",
		};
	}

	if (allowProjectDeletion) {
		console.log(`[safety-guard] ALLOWED project-local deletion: ${command}`);
		return undefined;
	}

	// Only user-escalated checks are optional; all path blocks above remain active.
	if (!state.permissionGatesEnabled) return undefined;

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
 * Handle read-equivalent tool calls (read/write/edit/grep/find) with path validation.
 * grep/find only carry an optional `path` search root: omitted path means cwd and is allowed.
 */
export const handleFileIOTools = async (
	toolName: "read" | "write" | "edit" | "grep" | "find",
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

	// write/edit: block entire discovered node_modules trees (package paths included).
	// bash/read may inspect specific packages; mutation stays forbidden.
	if (
		(toolName === "write" || toolName === "edit") &&
		isUnderDiscoveredNodeModules(resolvedPath)
	) {
		console.log(
			`[safety-guard] BLOCKED ${toolName} under discovered node_modules: ${resolvedPath}`
		);
		return {
			block: true,
			reason: "Write/edit under node_modules is blocked",
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

	// Only user-escalated checks are optional; all path blocks above remain active.
	if (!state.permissionGatesEnabled) return undefined;

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
	} else if (
		event.toolName === "read" ||
		event.toolName === "write" ||
		event.toolName === "edit" ||
		event.toolName === "grep" ||
		event.toolName === "find"
	) {
		return handleFileIOTools(event.toolName, event.input, ctx);
	}

	return undefined;
};

/**
 * Session start handler: Load config and set up whitelist/blacklist.
 */
export const onSessionStart = (event: SessionStartEvent, ctx: ExtensionContext) => {
	// Never carry an opt-in across sessions or failed config loads.
	state.permissionGatesEnabled = false;
	state.blockedPaths = loadGlobalBlockedPaths();
	const effectiveCwd = resolve(ctx.cwd || process.cwd());
	const nodeModulesDiscovery = discoverNodeModules(effectiveCwd);

	state.nodeModulesPaths = nodeModulesDiscovery.paths;
	state.nodeModulesInCwdTree = nodeModulesDiscovery.nodeModulesInCwdTree;

	console.log(
		`[safety-guard] node_modules locations=${nodeModulesDiscovery.paths.length}, ` +
		`inCwdTree=${nodeModulesDiscovery.nodeModulesInCwdTree}`
	);

	try {
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
				if (validation.blockedPaths !== undefined) {
					state.blockedPaths = validation.blockedPaths;
				}
				if (validation.allowedPaths) {
					state.allowedPaths = validation.allowedPaths.map(expandTilde);
				}
				if (validation.notificationsEnabled !== undefined) {
					state.notificationsEnabled = validation.notificationsEnabled;
				}
				state.permissionGatesEnabled = validation.permissionGatesEnabled ?? loadGlobalPermissionGatesEnabled();
				console.log(
					`[safety-guard] Config validated: ${state.allowedPaths.length} user-defined paths, notifications=${state.notificationsEnabled}`
				);
			}
		} else {
			state.permissionGatesEnabled = loadGlobalPermissionGatesEnabled();
			console.log("[safety-guard] No config found, using defaults (notify=true, global whitelist preserved)");
		}
		console.log(`[safety-guard] User permission gates enabled=${state.permissionGatesEnabled}`);

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
		state.permissionGatesEnabled = false;
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

	// Render the effective policy only after host/project settings have loaded.
	if (ctx.systemPrompt) {
		ctx.systemPrompt = appendSecurityPolicy(ctx.systemPrompt);
	}
	if (ctx.aiSystemMessage) {
		ctx.aiSystemMessage = appendSecurityPolicy(ctx.aiSystemMessage);
	}
};
