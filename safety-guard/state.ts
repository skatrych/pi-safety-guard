import { DEFAULT_BLOCKED_PATHS, compileBlockedPaths } from "./constants";

export const state = {
	blockedPaths: [...DEFAULT_BLOCKED_PATHS],
	blockedPathPatterns: compileBlockedPaths(DEFAULT_BLOCKED_PATHS),
	allowedPaths: [] as string[],
	notificationsEnabled: true,
	permissionGatesEnabled: false,
	configLoaded: false,
	nodeModulesPaths: [] as string[],
	nodeModulesInCwdTree: false,
};
