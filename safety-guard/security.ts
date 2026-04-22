import { resolve } from "node:path";
import { BLACKLIST, WHITELIST, COMMAND_NAME_TOKENS } from "./constants";
import { expandTilde } from "./utils";

/**
 * Path Security Decision Engine.
 *
 * BLACKLIST: Highest priority - evaluated FIRST
 * WHITELIST: Lower priority - evaluated SECOND
 * DEFAULT: Everything else requires consent
 */
export const checkPathSecurity = (path: string): "ALLOW" | "CONSENT_REQUIRED" | "BLOCK" => {
	if (BLACKLIST.some((p) => p.test(path))) {
		return "BLOCK";
	}
	if (WHITELIST.some((p) => p.test(path))) {
		return "ALLOW";
	}
	return "CONSENT_REQUIRED";
};

/**
 * Extract candidate file/directory paths from a bash command string.
 */
export const extractPathsFromCommand = (command: string, cwd: string): string[] => {
	// Split on shell token boundaries (spaces, semicolons, pipes, &&, ||)
	const tokens = command
		.split(/[\s;|&]+/)
		.map((t) => t.trim())
		.filter(Boolean);

	const paths: string[] = [];

	for (let token of tokens) {
		// Strip surrounding single or double quotes
		if (
			(token.startsWith('"') && token.endsWith('"')) ||
			(token.startsWith("'") && token.endsWith("'"))
		) {
			token = token.slice(1, -1);
		}

		// Skip flags/options
		if (token.startsWith("-")) continue;
		// Skip recognised command-name tokens (not path candidates)
		if (COMMAND_NAME_TOKENS.has(token)) continue;

		let candidate: string | null = null;

		if (token.startsWith("~/") || token === "~") {
			// Tilde path
			candidate = expandTilde(token);
		} else if (token.startsWith("/")) {
			// Absolute path
			candidate = token;
		} else if (token.startsWith("./") || token.startsWith("../")) {
			// Explicit relative path
			candidate = resolve(cwd, token);
		}

		if (candidate) {
			// Strip any trailing shell redirects captured in the token
			candidate = candidate.replace(/[<>|&;].*$/, "");
			paths.push(candidate);
		}
	}

	return paths;
};

/**
 * Check whether a bash command is attempting to access a blacklisted path.
 * Returns the first offending path found, or null if safe.
 */
export const findBlacklistedPathInCommand = (command: string, cwd: string): string | null => {
	const paths = extractPathsFromCommand(command, cwd);
	for (const p of paths) {
		if (BLACKLIST.some((bl) => bl.test(p))) {
			return p;
		}
	}
	return null;
};
