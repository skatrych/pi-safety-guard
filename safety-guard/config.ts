import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { expandTilde } from "./utils";

/**
 * Validate config schema:
 * - allowedPaths must be array of strings
 * - notificationsEnabled must be boolean (strict type check)
 * - permissionGatesEnabled must be boolean or "on"/"off"
 */
export const validateConfig = (config: unknown): {
	valid: true;
	allowedPaths?: string[];
	notificationsEnabled?: boolean;
	permissionGatesEnabled?: boolean;
} | { valid: false; errors: string[] } => {
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

	const permissionGatesRaw = (config as Record<string, unknown>)["extensions.permissionGatesEnabled"];
	if (
		permissionGatesRaw !== undefined &&
		typeof permissionGatesRaw !== "boolean" && permissionGatesRaw !== "on" && permissionGatesRaw !== "off"
	) {
		errors.push("permissionGatesEnabled must be boolean or on/off");
	}

	if (errors.length > 0) {
		return { valid: false, errors };
	}

	return {
		valid: true,
		allowedPaths: Array.isArray(allowedPathsRaw) ? (allowedPathsRaw as string[]) : undefined,
		permissionGatesEnabled: permissionGatesRaw === undefined ?
			undefined : permissionGatesRaw === true || permissionGatesRaw === "on",
		notificationsEnabled:
			typeof (config as Record<string, unknown>)["extensions.notificationsEnabled"] === "boolean"
				? ((config as Record<string, unknown>)["extensions.notificationsEnabled"] as boolean)
				: undefined,
	};
};

/** Read only the approval toggle from Pi's global settings; leave path configuration lookup unchanged. */
export const loadGlobalPermissionGatesEnabled = (): boolean => {
	const agentDir = expandTilde(process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent"));
	const settingsPath = join(agentDir, "settings.json");
	try {
		if (!existsSync(settingsPath)) return false;
		const validation = validateConfig(JSON.parse(readFileSync(settingsPath, "utf8")));
		if (!validation.valid) {
			console.error(`[safety-guard] Global config validation failed: ${validation.errors.join(", ")}`);
			return false;
		}
		return validation.permissionGatesEnabled ?? false;
	} catch (error: unknown) {
		console.error("[safety-guard] Global permission gate setting load failed", error);
		return false;
	}
};
