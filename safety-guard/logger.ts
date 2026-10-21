import { appendFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { inspect } from "node:util";
import { getAgentDir } from "./utils";

// Enforced log filename; lives inside the Pi agent directory next to Pi's own
// state, so logs are findable in the native location and never touch the TUI
// (console output renders as a layer over the input field in interactive mode
// and corrupts stdout in JSON/print modes).
const LOG_FILENAME = "safety-guard.log";

// Control characters (incl. ESC, which enables ANSI injection) are dropped from messages.
// eslint-disable-next-line no-control-regex -- intentional: strip every control character
const CONTROL_CHARS = new RegExp("[\\u0000-\\u001f\\u007f]", "g");

// Size cap for the always-on log: once the active file exceeds this it is
// rotated to safety-guard.log.1 (previous generation overwritten) before appending.
const MAX_LOG_BYTES = 5 * 1024 * 1024;

/** Log file path: <agent-dir>/logs/safety-guard.log */
const getLogPath = (): string => {
	return join(getAgentDir(), "logs", LOG_FILENAME);
};

/**
 * Render an unknown thrown value for logging: full stack for Error instances,
 * util.inspect for anything else (no [object Object]).
 */
export const describeError = (error: unknown): string => {
	if (error instanceof Error) {
		return error.stack || error.message;
	}
	return inspect(error);
};

/** True when success-level (ALLOWED) lines should be logged as well. */
const debugEnabled = (): boolean => {
	return process.env.SAFETY_GUARD_LOG === "debug";
};

/**
 * Rotate the active log to .1 once it exceeds the size cap. Rename preserves
 * the file's 0600 mode. A missing file (first run) or a failed rename must
 * not break logging; the append is attempted either way.
 */
const rotateIfLarge = (logPath: string): void => {
	try {
		if (statSync(logPath).size > MAX_LOG_BYTES) {
			renameSync(logPath, `${logPath}.1`);
		}
	} catch {
		// First run (ENOENT) or non-fatal rotation failure.
	}
};

const writeLine = (level: "info" | "error" | "debug", message: string): void => {
	try {
		const logPath = getLogPath();
		mkdirSync(dirname(logPath), { recursive: true, mode: 0o700 });
		rotateIfLarge(logPath);
		// One physical line per entry: escape newlines, drop remaining control chars.
		const safe = message.replace(/[\r\n]+/g, "\\n").replace(CONTROL_CHARS, "");
		appendFileSync(logPath, `${new Date().toISOString()} [${level}] [safety-guard] ${safe}\n`, {
			mode: 0o600,
		});
	} catch {
		// Logging must never break a safety check or the TUI.
	}
};

/** Append an info-level line to the safety-guard log file. */
export const logInfo = (message: string): void => {
	writeLine("info", message);
};

/** Append an error-level line; an optional error is rendered via describeError. */
export const logError = (message: string, error?: unknown): void => {
	writeLine("error", error === undefined ? message : `${message}: ${describeError(error)}`);
};

/**
 * Append a success-level line (ALLOWED events). Noisy in steady state, so it is
 * only written when SAFETY_GUARD_LOG=debug; BLOCKED/error lines stay always-on.
 */
export const logDebug = (message: string): void => {
	if (!debugEnabled()) return;
	writeLine("debug", message);
};
