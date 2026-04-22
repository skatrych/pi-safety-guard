import { join } from "node:path";
import { HOME_DIR } from "./constants";

/**
 * Sanitize command: Remove null bytes and zero-width characters.
 * Prevents pattern injection attacks.
 */
export const sanitizeCommand = (cmd: string): string => {
	return cmd
		.replace(/[\u0000-\u001F\u007F]/g, "")
		.replace(/\u200B/g, "")
		.replace(/\u200C/g, "")
		.replace(/\u200D/g, "");
};

/**
 * Expand tilde to home directory using cached HOME_DIR constant.
 */
export const expandTilde = (path: string): string => {
	if (path.startsWith("~")) {
		return join(HOME_DIR, path.slice(1));
	}
	return path;
};

/**
 * Check for path traversal attacks before path resolution.
 */
export const hasPathTraversal = (path: string): boolean => {
	// Matches: "../", "/..", "/../", or a bare ".." token
	return /(?:^|\/)\.\.(\/|$)/.test(path);
};
