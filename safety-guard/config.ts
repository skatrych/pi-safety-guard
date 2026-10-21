import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { getAgentDir } from "./utils";
import { logError } from "./logger";
import { DEFAULT_BLOCKED_PATHS } from "./constants";

/**
 * Validate config schema:
 * - allowedPaths must be array of strings
 * - blockedPaths must be array of non-empty strings without control characters
 * - notificationsEnabled must be boolean (strict type check)
 * - permissionGatesEnabled must be boolean or "on"/"off"
 */
export const validateConfig = (config: unknown): {
	valid: true;
	allowedPaths?: string[];
	blockedPaths?: string[];
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

	const blockedPathsRaw = (config as Record<string, unknown>)["extensions.blockedPaths"];
	if (blockedPathsRaw !== undefined) {
		if (!Array.isArray(blockedPathsRaw)) {
			errors.push("blockedPaths must be an array");
		} else if (blockedPathsRaw.some((path) =>
			typeof path !== "string" || path.trim().length === 0 ||
			Array.from(path).some((char) => char.charCodeAt(0) <= 0x1F || char.charCodeAt(0) === 0x7F)
		)) {
			errors.push("blockedPaths must contain non-empty strings without control characters");
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
		blockedPaths: Array.isArray(blockedPathsRaw) ? (blockedPathsRaw as string[]) : undefined,
		permissionGatesEnabled: permissionGatesRaw === undefined ?
			undefined : permissionGatesRaw === true || permissionGatesRaw === "on",
		notificationsEnabled:
			typeof (config as Record<string, unknown>)["extensions.notificationsEnabled"] === "boolean"
				? ((config as Record<string, unknown>)["extensions.notificationsEnabled"] as boolean)
				: undefined,
	};
};

/** Read host settings without changing the legacy allowed-path/notification lookup. */
const loadGlobalConfig = (): Extract<ReturnType<typeof validateConfig>, { valid: true }> | undefined => {
	const settingsPath = join(getAgentDir(), "settings.json");
	try {
		if (!existsSync(settingsPath)) return undefined;
		const validation = validateConfig(JSON.parse(readFileSync(settingsPath, "utf8")));
		if (!validation.valid) {
			logError(`Global config validation failed: ${validation.errors.join(", ")}`);
			return undefined;
		}
		return validation;
	} catch (error: unknown) {
		logError("Global settings load failed", error);
		return undefined;
	}
};

export const loadGlobalPermissionGatesEnabled = (): boolean => {
	return loadGlobalConfig()?.permissionGatesEnabled ?? false;
};

export const loadGlobalBlockedPaths = (): string[] => {
	return loadGlobalConfig()?.blockedPaths ?? [...DEFAULT_BLOCKED_PATHS];
};
