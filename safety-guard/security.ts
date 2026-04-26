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

const isLikelyBarePathToken = (token: string): boolean => {
	// Conservative bare-token heuristic to reduce false positives.
	if (token.length === 0) return false;
	if (token.startsWith("$")) return false; // variable expansion / env references
	if (token.includes("=")) return false; // env assignment / key=value args
	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(token)) return false; // URLs
	if (/[*?\[\]{}]/.test(token)) return false; // shell globs / brace expansion

	return token.startsWith(".") || token.includes("/") || token.includes(".");
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

		// Remove trailing shell redirect/operator fragments
		token = token.replace(/[<>|&;].*$/, "");
		if (!token) continue;

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
		} else if (isLikelyBarePathToken(token)) {
			// Bare filename/path token resolved relative to cwd
			candidate = resolve(cwd, token);
		}

		if (candidate) {
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
