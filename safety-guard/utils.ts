import { join } from "node:path";
import { HOME_DIR } from "./constants";

/**
 * Sanitize command: Remove null bytes and zero-width characters.
 * Prevents pattern injection attacks.
 */
export const sanitizeCommand = (cmd: string): string => {
	const withoutControlChars = Array.from(cmd)
		.filter((char) => {
			const code = char.charCodeAt(0);
			const isBlockedControlCode = code <= 0x08 || code === 0x0B || code === 0x0C ||
				(code >= 0x0E && code <= 0x1F) || code === 0x7F;
			return !isBlockedControlCode;
		})
		.join("");
	return withoutControlChars
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
 * Pi agent directory: $PI_CODING_AGENT_DIR (with ~ expansion) or ~/.pi/agent.
 * Shared by config lookup (config.ts) and logging (logger.ts).
 */
export const getAgentDir = (): string => {
	return expandTilde(process.env.PI_CODING_AGENT_DIR || join(HOME_DIR, ".pi", "agent"));
};

/**
 * Check for path traversal attacks before path resolution.
 */
export const hasPathTraversal = (path: string): boolean => {
	// Matches: "../", "/..", "/../", or a bare ".." token
	return /(?:^|\/)\.\.(\/|$)/.test(path);
};
