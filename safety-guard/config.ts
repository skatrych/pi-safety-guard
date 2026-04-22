/**
 * Validate config schema:
 * - allowedPaths must be array of strings
 * - notificationsEnabled must be boolean (strict type check)
 */
export const validateConfig = (config: unknown): { valid: true; allowedPaths?: string[]; notificationsEnabled?: boolean } | { valid: false; errors: string[] } => {
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
