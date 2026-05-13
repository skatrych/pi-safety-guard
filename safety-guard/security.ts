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
	if (/\s/.test(token)) return false; // bare path tokens should not include unescaped whitespace
	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(token)) return false; // URLs
	const hasGlobOrBraceChars = ["*", "?", "[", "]", "{", "}"].some((char) => token.includes(char));
	if (hasGlobOrBraceChars) return false; // shell globs / brace expansion
	if (/[()'`]/.test(token)) return false; // likely code snippets, not shell path operands

	return token.startsWith(".") || token.includes("/") || token.includes(".");
};

type ShellToken = {
	type: "word" | "operator";
	value: string;
};

type PendingHeredoc = {
	delimiter: string;
	stripLeadingTabs: boolean;
};

const REDIRECT_OPERATORS = new Set([
	">",
	">>",
	"<",
	"1>",
	"1>>",
	"1<",
	"2>",
	"2>>",
	"2<",
	"&>",
	"&>>",
]);

const COMMAND_SEPARATORS = new Set([";", "&&", "||", "|", "&"]);

const isOperatorStart = (line: string, index: number): boolean => {
	const c = line[index];
	if (c === ";" || c === "|" || c === "<" || c === ">" || c === "&") return true;
	if ((c === "1" || c === "2") && index + 1 < line.length) {
		const n = line[index + 1];
		return n === ">" || n === "<";
	}
	return false;
};

const matchOperator = (line: string, index: number): { op: string; length: number } | null => {
	const rest = line.slice(index);
	if (rest.startsWith("2>&1")) return { op: "2>&1", length: 4 };
	if (rest.startsWith("1>&2")) return { op: "1>&2", length: 4 };
	if (rest.startsWith(">&1")) return { op: ">&1", length: 3 };
	if (rest.startsWith(">&2")) return { op: ">&2", length: 3 };
	if (rest.startsWith("<&0")) return { op: "<&0", length: 3 };
	if (rest.startsWith("&&")) return { op: "&&", length: 2 };
	if (rest.startsWith("||")) return { op: "||", length: 2 };
	if (rest.startsWith("&>>")) return { op: "&>>", length: 3 };
	if (rest.startsWith("&>")) return { op: "&>", length: 2 };
	if (rest.startsWith("1>>")) return { op: "1>>", length: 3 };
	if (rest.startsWith("2>>")) return { op: "2>>", length: 3 };
	if (rest.startsWith("1>")) return { op: "1>", length: 2 };
	if (rest.startsWith("2>")) return { op: "2>", length: 2 };
	if (rest.startsWith("1<")) return { op: "1<", length: 2 };
	if (rest.startsWith("2<")) return { op: "2<", length: 2 };
	if (rest.startsWith(">>")) return { op: ">>", length: 2 };
	if (rest.startsWith("<<-")) return { op: "<<-", length: 3 };
	if (rest.startsWith("<<")) return { op: "<<", length: 2 };
	if (rest.startsWith(">")) return { op: ">", length: 1 };
	if (rest.startsWith("<")) return { op: "<", length: 1 };
	if (rest.startsWith("|")) return { op: "|", length: 1 };
	if (rest.startsWith(";")) return { op: ";", length: 1 };
	if (rest.startsWith("&")) return { op: "&", length: 1 };
	return null;
};

const tokenizeLine = (line: string): ShellToken[] => {
	const tokens: ShellToken[] = [];
	let i = 0;

	while (i < line.length) {
		const iterationStart = i;
		const c = line[i];
		if (c === " " || c === "\t") {
			i++;
			continue;
		}

		if (c === "#") {
			break;
		}

		const operator = matchOperator(line, i);
		if (operator) {
			tokens.push({ type: "operator", value: operator.op });
			i += operator.length;
			continue;
		}

		let token = "";
		let inSingle = false;
		let inDouble = false;

		while (i < line.length) {
			const ch = line[i];

			if (!inSingle && !inDouble && (ch === " " || ch === "\t")) {
				break;
			}

			if (!inSingle && !inDouble && isOperatorStart(line, i)) {
				break;
			}

			if (ch === "'" && !inDouble) {
				inSingle = !inSingle;
				i++;
				continue;
			}

			if (ch === "\"" && !inSingle) {
				inDouble = !inDouble;
				i++;
				continue;
			}

			if (ch === "\\") {
				if (inSingle) {
					token += ch;
					i++;
					continue;
				}

				if (i + 1 >= line.length) {
					token += ch;
					i++;
					continue;
				}

				const next = line[i + 1];
				if (!inDouble) {
					token += next;
					i += 2;
					continue;
				}

				if (next === "\"" || next === "\\" || next === "$" || next === "`") {
					token += next;
				} else {
					token += ch + next;
				}
				i += 2;
				continue;
			}

			token += ch;
			i++;
		}

		if (token) {
			tokens.push({ type: "word", value: token });
		}

		if (i === iterationStart) {
			i++;
		}
	}

	return tokens;
};

const isEnvAssignmentToken = (token: string): boolean => {
	return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(token);
};

const resolvePathCandidate = (token: string, cwd: string): string | null => {
	if (token.startsWith("~/") || token === "~") {
		return expandTilde(token);
	}
	if (token.startsWith("/")) {
		return token;
	}
	if (token.startsWith("./") || token.startsWith("../")) {
		return resolve(cwd, token);
	}
	if (isLikelyBarePathToken(token)) {
		return resolve(cwd, token);
	}
	return null;
};

/**
 * Extract candidate file/directory paths from a bash command string.
 */
export const extractPathsFromCommand = (command: string, cwd: string): string[] => {
	const paths: string[] = [];
	const lines = command.replace(/\r\n?/g, "\n").split("\n");
	let lineIndex = 0;

	while (lineIndex < lines.length) {
		const line = lines[lineIndex];
		const tokens = tokenizeLine(line);
		const pendingHeredocs: PendingHeredoc[] = [];
		let expectCommandName = true;
		let expectRedirectTarget = false;

		for (let i = 0; i < tokens.length; i++) {
			const token = tokens[i];
			if (token.type === "operator") {
				if (token.value === "<<" || token.value === "<<-") {
					expectRedirectTarget = false;
					const next = tokens[i + 1];
					if (next && next.type === "word") {
						const delimiter = next.value;
						if (delimiter.length > 0) {
							pendingHeredocs.push({
								delimiter,
								stripLeadingTabs: token.value === "<<-",
							});
						}
						i++;
					}
					continue;
				}

				if (REDIRECT_OPERATORS.has(token.value)) {
					expectRedirectTarget = true;
					continue;
				}

				if (COMMAND_SEPARATORS.has(token.value)) {
					expectCommandName = true;
					expectRedirectTarget = false;
					continue;
				}

				continue;
			}

			const raw = token.value.trim();
			if (!raw) {
				expectRedirectTarget = false;
				continue;
			}

			if (expectRedirectTarget) {
				const candidate = resolvePathCandidate(raw, cwd);
				if (candidate) {
					paths.push(candidate);
				}
				expectRedirectTarget = false;
				expectCommandName = false;
				continue;
			}

			if (expectCommandName) {
				if (isEnvAssignmentToken(raw)) {
					continue;
				}
				if (!COMMAND_NAME_TOKENS.has(raw)) {
					const candidate = resolvePathCandidate(raw, cwd);
					if (candidate) {
						paths.push(candidate);
					}
				}
				expectCommandName = false;
				continue;
			}

			if (raw.startsWith("-")) {
				continue;
			}

			const candidate = resolvePathCandidate(raw, cwd);
			if (candidate) {
				paths.push(candidate);
			}
		}

		if (pendingHeredocs.length > 0) {
			lineIndex++;
			for (const heredoc of pendingHeredocs) {
				while (lineIndex < lines.length) {
					const candidateLine = heredoc.stripLeadingTabs ? lines[lineIndex].replace(/^\t+/, "") :
						lines[lineIndex];
					if (candidateLine === heredoc.delimiter) {
						break;
					}
					lineIndex++;
				}
				if (lineIndex < lines.length) {
					lineIndex++;
				}
			}
			continue;
		}

		lineIndex++;
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
