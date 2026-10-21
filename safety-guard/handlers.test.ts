import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
	mkdirSync,
	mkdtempSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { discoverNodeModules } from "./node-modules";
import { handleBashTools, handleFileIOTools, handleToolCall, onSessionStart } from "./handlers";
import { state } from "./state";
import { BLACKLIST, WHITELIST, HOME_DIR } from "./constants";
import { appendSecurityPolicy } from "./prompt";
import { checkPathSecurity } from "./security";
import { validateConfig } from "./config";

const createFixture = (): string => {
	return mkdtempSync(join(tmpdir(), "safety-guard-"));
};

const cleanupFixture = (dir: string): void => {
	rmSync(dir, { recursive: true, force: true });
};

type MockCtx = Parameters<typeof onSessionStart>[1];

const makeCtx = (cwd: string): MockCtx => ({
	cwd,
	hasUI: false,
	ui: {
		confirm: async () => false,
		notify: () => {},
	},
} as MockCtx);

type StateSnapshot = {
	blockedPaths: string[];
	blockedPathPatterns: RegExp[];
	allowedPaths: string[];
	notificationsEnabled: boolean;
	permissionGatesEnabled: boolean;
	configLoaded: boolean;
	nodeModulesPaths: string[];
	nodeModulesInCwdTree: boolean;
	blacklist: RegExp[];
	whitelist: RegExp[];
};

let stateSnapshot: StateSnapshot;

const captureState = (): StateSnapshot => ({
	blockedPaths: [...state.blockedPaths],
	blockedPathPatterns: [...state.blockedPathPatterns],
	allowedPaths: [...state.allowedPaths],
	notificationsEnabled: state.notificationsEnabled,
	permissionGatesEnabled: state.permissionGatesEnabled,
	configLoaded: state.configLoaded,
	nodeModulesPaths: [...state.nodeModulesPaths],
	nodeModulesInCwdTree: state.nodeModulesInCwdTree,
	blacklist: [...BLACKLIST],
	whitelist: [...WHITELIST],
});

const restoreState = (snap: StateSnapshot): void => {
	state.blockedPaths = snap.blockedPaths;
	state.blockedPathPatterns = snap.blockedPathPatterns;
	state.allowedPaths = snap.allowedPaths;
	state.notificationsEnabled = snap.notificationsEnabled;
	state.permissionGatesEnabled = snap.permissionGatesEnabled;
	state.configLoaded = snap.configLoaded;
	state.nodeModulesPaths = snap.nodeModulesPaths;
	state.nodeModulesInCwdTree = snap.nodeModulesInCwdTree;
	BLACKLIST.length = 0;
	BLACKLIST.push(...snap.blacklist);
	WHITELIST.length = 0;
	WHITELIST.push(...snap.whitelist);
};

test("config: permission gates only accept booleans and on/off strings", () => {
	for (const value of [true, false, "on", "off"]) {
		const result = validateConfig({ "extensions.permissionGatesEnabled": value });
		assert.equal(result.valid, true);
		if (result.valid) assert.equal(result.permissionGatesEnabled, value === true || value === "on");
	}
	for (const value of [1, 0, null, "true", "false", "ON", [], {}]) {
		assert.equal(validateConfig({ "extensions.permissionGatesEnabled": value }).valid, false);
	}
});

test("config: blocked paths require non-empty strings without control characters", () => {
	for (const value of [[], ["~/private", "/host/secrets.json", "private/.env.*"]]) {
		const result = validateConfig({ "extensions.blockedPaths": value });
		assert.equal(result.valid, true);
		if (result.valid) assert.deepEqual(result.blockedPaths, value);
	}
	for (const value of [null, "~/private", {}, [1], [null], [""], ["   "], ["secret\u0000"], ["secret\nfile"]]) {
		assert.equal(validateConfig({ "extensions.blockedPaths": value }).valid, false);
	}
});

const initSession = (cwd: string): void => {
	onSessionStart({} as Parameters<typeof onSessionStart>[0], makeCtx(cwd));
};

test("discovery: detects cwd node_modules and sets nodeModulesInCwdTree", () => {
	const fixture = createFixture();
	try {
		mkdirSync(join(fixture, "node_modules"));
		const result = discoverNodeModules(fixture);
		assert.ok(result.paths.includes(join(fixture, "node_modules")));
		assert.equal(result.nodeModulesInCwdTree, true);
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: detects immediate-child node_modules and sets nodeModulesInCwdTree", () => {
	const fixture = createFixture();
	try {
		mkdirSync(join(fixture, "packages", "node_modules"), { recursive: true });
		const result = discoverNodeModules(fixture);
		assert.ok(result.paths.includes(join(fixture, "packages", "node_modules")));
		assert.equal(result.nodeModulesInCwdTree, true);
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: parent-only hit does not set nodeModulesInCwdTree", () => {
	const fixture = createFixture();
	try {
		const parent = join(fixture, "parent");
		const child = join(parent, "project");
		mkdirSync(child, { recursive: true });
		mkdirSync(join(parent, "node_modules"));
		const result = discoverNodeModules(child);
		assert.ok(result.paths.includes(join(parent, "node_modules")));
		assert.equal(result.nodeModulesInCwdTree, false);
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: detects cwd, parent, and immediate-child locations together", () => {
	const fixture = createFixture();
	try {
		const parent = join(fixture, "parent");
		const child = join(parent, "project");
		mkdirSync(join(child, "packages", "node_modules"), { recursive: true });
		mkdirSync(join(child, "node_modules"));
		mkdirSync(join(parent, "node_modules"));
		const result = discoverNodeModules(child);
		assert.ok(result.paths.includes(join(child, "node_modules")));
		assert.ok(result.paths.includes(join(parent, "node_modules")));
		assert.ok(result.paths.includes(join(child, "packages", "node_modules")));
		assert.equal(result.nodeModulesInCwdTree, true);
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: ignores regular file named node_modules", () => {
	const fixture = createFixture();
	try {
		writeFileSync(join(fixture, "node_modules"), "not a directory");
		const result = discoverNodeModules(fixture);
		assert.ok(!result.paths.includes(join(fixture, "node_modules")));
		assert.equal(result.nodeModulesInCwdTree, false);
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: counts node_modules symlink to directory with lexical path", () => {
	const fixture = createFixture();
	try {
		const target = join(fixture, "actual-deps");
		mkdirSync(target);
		const linkPath = join(fixture, "node_modules");
		try {
			symlinkSync(target, linkPath);
		} catch {
			return; // skip if symlink creation unavailable
		}
		const result = discoverNodeModules(fixture);
		assert.ok(result.paths.includes(linkPath));
		assert.equal(result.nodeModulesInCwdTree, true);
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: missing cwd does not throw", () => {
	const missing = join(tmpdir(), "safety-guard-missing-" + Date.now());
	const result = discoverNodeModules(missing);
	assert.deepEqual(result, { paths: [], nodeModulesInCwdTree: false });
});

test("discovery: filesystem root does not duplicate candidate", () => {
	const root = sep === "\\" ? "C:\\" : "/";
	const result = discoverNodeModules(root);
	const rootCandidate = join(root, "node_modules");
	const matches = result.paths.filter((p) => p === rootCandidate);
	assert.ok(matches.length <= 1);
});

test("discovery: does not discover grandchild node_modules", () => {
	const fixture = createFixture();
	try {
		mkdirSync(join(fixture, "packages", "ui", "node_modules"), { recursive: true });
		const result = discoverNodeModules(fixture);
		assert.ok(!result.paths.includes(join(fixture, "packages", "ui", "node_modules")));
	} finally {
		cleanupFixture(fixture);
	}
});

test("discovery: does not discover grandparent node_modules", () => {
	const fixture = createFixture();
	try {
		const grandparent = join(fixture, "grandparent");
		const parent = join(grandparent, "parent");
		const child = join(parent, "project");
		mkdirSync(child, { recursive: true });
		mkdirSync(join(grandparent, "node_modules"));
		const result = discoverNodeModules(child);
		assert.ok(!result.paths.includes(join(grandparent, "node_modules")));
	} finally {
		cleanupFixture(fixture);
	}
});

describe("handler integration", { concurrency: false }, () => {
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		stateSnapshot = captureState();
		previousAgentDir = process.env.PI_CODING_AGENT_DIR;
		agentDir = createFixture();
		process.env.PI_CODING_AGENT_DIR = agentDir;
	});

	afterEach(() => {
		restoreState(stateSnapshot);
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
		cleanupFixture(agentDir);
	});

	const writeSettings = (dir: string, config: unknown): void => {
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "settings.json"), JSON.stringify(config));
	};

	for (const enabled of [false, true]) {
		test(`blocked paths: configured files and directories block silently (gates=${enabled})`, async () => {
			const fixture = createFixture();
			try {
				writeSettings(join(fixture, ".pi"), {
					"extensions.blockedPaths": ["private+data/", "secrets.json", "~/host-private", "private/.token.*"],
					"extensions.allowedPaths": [fixture, "~/host-private"],
					"extensions.permissionGatesEnabled": enabled,
				});
				initSession(fixture);
				for (const hasUI of [false, true]) {
					const ctx = makeCtx(fixture);
					ctx.hasUI = hasUI;
					ctx.ui.confirm = async () => assert.fail("Blocked paths must never prompt");
					ctx.ui.notify = () => assert.fail("Blocked paths must never notify");
					for (const path of [
						"private+data", "private+data/file.txt", "secrets.json", "~/host-private/key", "private/.token.local",
					]) {
						for (const tool of ["read", "write", "edit", "grep", "find"] as const) {
							assert.ok((await handleFileIOTools(tool, { path }, ctx))?.block, `${tool} ${path}`);
						}
						assert.ok((await handleBashTools({ command: `cat '${path}'` }, ctx))?.block, path);
						assert.ok((await handleBashTools({ command: `rm -rf '${path}'` }, ctx))?.block, path);
					}
					for (const path of [
						"private+data-backup/file.txt", "privateXdata/file.txt", "secrets.json.bak", "private/.token",
					]) {
						assert.equal(await handleFileIOTools("read", { path }, ctx), undefined, path);
					}
				}
				assert.equal(checkPathSecurity("/etc/passwd"), "CONSENT_REQUIRED");
				const prompt = appendSecurityPolicy("base prompt");
				assert.ok(prompt.startsWith("base prompt"));
				assert.ok(prompt.includes(join(fixture, "private+data")));
				assert.ok(!prompt.includes("/etc/"));
			} finally {
				cleanupFixture(fixture);
			}
		});
	}

	test("blocked paths: session prompt fields use the loaded project policy", () => {
		const fixture = createFixture();
		try {
			writeSettings(join(fixture, ".pi"), { "extensions.blockedPaths": ["host-specific-secret"] });
			const ctx = { ...makeCtx(fixture), systemPrompt: "system", aiSystemMessage: "message" };
			onSessionStart({} as Parameters<typeof onSessionStart>[0], ctx);
			assert.ok(ctx.systemPrompt.startsWith("system"));
			assert.ok(ctx.aiSystemMessage.startsWith("message"));
			for (const prompt of [ctx.systemPrompt, ctx.aiSystemMessage]) {
				assert.ok(prompt.includes(join(fixture, "host-specific-secret")));
				assert.ok(!prompt.includes("/etc/"));
			}
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("blocked paths: global host list is inherited, explicit project list replaces it", () => {
		const fixture = createFixture();
		try {
			const hostSecret = join(agentDir, "host-secret");
			writeSettings(agentDir, { "extensions.blockedPaths": [hostSecret] });
			initSession(fixture);
			assert.equal(checkPathSecurity(hostSecret), "BLOCK");
			writeSettings(join(fixture, ".pi"), { "extensions.notificationsEnabled": false });
			initSession(fixture);
			assert.equal(checkPathSecurity(hostSecret), "BLOCK");
			writeSettings(join(fixture, ".pi"), { "extensions.blockedPaths": ["project-secret"] });
			initSession(fixture);
			assert.notEqual(checkPathSecurity(hostSecret), "BLOCK");
			assert.equal(checkPathSecurity(join(fixture, "project-secret")), "BLOCK");
			writeSettings(join(fixture, ".pi"), { "extensions.blockedPaths": [] });
			initSession(fixture);
			assert.notEqual(checkPathSecurity(join(fixture, "project-secret")), "BLOCK");
			assert.notEqual(checkPathSecurity("/etc/passwd"), "BLOCK");
			assert.equal(checkPathSecurity(join(fixture, ".env")), "BLOCK");
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("blocked paths: bundled defaults protect sensitive roots and home env variants", () => {
		const fixture = createFixture();
		try {
			initSession(fixture);
			for (const path of [
				join(HOME_DIR, ".ssh"), join(HOME_DIR, ".ssh", "config"), join(HOME_DIR, ".env.local"), "/etc", "/etc/passwd",
			]) {
				assert.equal(checkPathSecurity(path), "BLOCK", path);
			}
			assert.notEqual(checkPathSecurity(join(HOME_DIR, ".ssh-backup", "config")), "BLOCK");
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("blocked paths: invalid or missing project settings reset custom rules to host policy", () => {
		const fixture = createFixture();
		try {
			const hostSecret = join(agentDir, "host-secret");
			writeSettings(agentDir, { "extensions.blockedPaths": [hostSecret] });
			for (const config of [{}, { "extensions.blockedPaths": [42] }, "{ malformed"]) {
				writeSettings(join(fixture, ".pi"), { "extensions.blockedPaths": ["old-secret"] });
				initSession(fixture);
				assert.equal(checkPathSecurity(join(fixture, "old-secret")), "BLOCK");
				writeSettings(join(fixture, ".pi"), config);
				if (typeof config === "string") writeFileSync(join(fixture, ".pi", "settings.json"), config);
				initSession(fixture);
				assert.notEqual(checkPathSecurity(join(fixture, "old-secret")), "BLOCK");
				assert.equal(checkPathSecurity(hostSecret), "BLOCK");
				assert.equal(checkPathSecurity(join(fixture, "nested", ".env.local")), "BLOCK");
			}
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("blocked paths: malformed global policy falls back to bundled defaults", () => {
		const fixture = createFixture();
		try {
			writeSettings(agentDir, { "extensions.blockedPaths": [] });
			initSession(fixture);
			assert.notEqual(checkPathSecurity("/etc/passwd"), "BLOCK");
			writeFileSync(join(agentDir, "settings.json"), "{ malformed");
			initSession(fixture);
			assert.equal(checkPathSecurity("/etc/passwd"), "BLOCK");
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("blocked paths: node_modules prune and deletion exceptions cannot override configured policy", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			writeSettings(join(fixture, ".pi"), {
				"extensions.blockedPaths": ["node_modules", "private", "nested/private"],
			});
			initSession(fixture);
			const ctx = makeCtx(fixture);
			for (const command of [
				"find . -path ./node_modules -prune -o -type f -print",
				"rm -rf ./node_modules",
				"rm -f safe.txt && cat private/key",
				"rm -rf ./node_modules && cat private/key",
				"cd nested && rm -rf private",
			]) {
				assert.ok((await handleBashTools({ command }, ctx))?.block, command);
			}
		} finally {
			cleanupFixture(fixture);
		}
	});

	for (const value of [undefined, false, "off", true, "on"]) {
		test(`permission gates: setting ${String(value)} controls both approval branches`, async () => {
			const fixture = createFixture();
			try {
				writeSettings(join(fixture, ".pi"), { "extensions.permissionGatesEnabled": value });
				initSession(fixture);
				const enabled = value === true || value === "on";
				assert.equal(state.permissionGatesEnabled, enabled);
				for (const hasUI of [true, false]) {
					const ctx = makeCtx(fixture);
					ctx.hasUI = hasUI;
					let prompts = 0;
					let notifications = 0;
					ctx.ui.confirm = async () => {
						prompts++;
						return false;
					};
					ctx.ui.notify = () => {
						notifications++;
					};
					const bash = await handleBashTools({ command: "helm uninstall release" }, ctx);
					assert.equal(bash?.block === true, enabled);
					for (const tool of ["read", "write", "edit", "grep", "find"] as const) {
						const file = await handleFileIOTools(tool, { path: join(agentDir, "outside.txt") }, ctx);
						assert.equal(file?.block === true, enabled);
					}
					assert.equal(prompts, enabled && hasUI ? 6 : 0);
					assert.equal(notifications, enabled && hasUI ? 6 : 0);
				}
			} finally {
				cleanupFixture(fixture);
			}
		});
	}

	test("permission gates: enabled prompts await user approval", async () => {
		const fixture = createFixture();
		try {
			writeSettings(join(fixture, ".pi"), { "extensions.permissionGatesEnabled": true });
			initSession(fixture);
			const ctx = makeCtx(fixture);
			ctx.hasUI = true;
			let approve!: (value: boolean) => void;
			ctx.ui.confirm = () => new Promise<boolean>((resolve) => {
				approve = resolve;
			});
			for (const operation of [
				() => handleBashTools({ command: "helm uninstall release" }, ctx),
				() => handleFileIOTools("read", { path: join(agentDir, "outside.txt") }, ctx),
			]) {
				let settled = false;
				const pending = operation().then((result) => {
					settled = true;
					return result;
				});
				await Promise.resolve();
				assert.equal(settled, false);
				approve(true);
				assert.equal(await pending, undefined);
			}
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: grep and find omit path for cwd search; external path follows consent flow", async () => {
		const fixture = createFixture();
		try {
			writeSettings(join(fixture, ".pi"), { "extensions.permissionGatesEnabled": true });
			initSession(fixture);
			const ctx = makeCtx(fixture);
			ctx.hasUI = true;
			let prompts = 0;
			ctx.ui.confirm = async () => {
				prompts++;
				return false;
			};
			const dispatch = (tool: "grep" | "find", input: { pattern: string; path?: string }) => {
				const event = { type: "tool_call", toolCallId: "1", toolName: tool, input };
				return handleToolCall(event as Parameters<typeof handleToolCall>[0], ctx);
			};
			assert.equal(await dispatch("grep", { pattern: "token" }), undefined);
			assert.equal(await dispatch("find", { pattern: "*.env" }), undefined);
			assert.equal(await dispatch("grep", { pattern: "x", path: "sub/file.txt" }), undefined);
			assert.equal(prompts, 0);
			const outside = await dispatch("find", { pattern: "*", path: join(agentDir, "outside.txt") });
			assert.equal(outside?.block === true, true);
			assert.equal(prompts, 1);
		} finally {
			cleanupFixture(fixture);
		}
	});

	for (const enabled of [false, true]) {
		test(`permission gates: protected paths still block without prompting (enabled=${enabled})`, async () => {
			const fixture = createFixture();
			try {
				mkdirSync(join(fixture, "node_modules"));
				writeSettings(join(fixture, ".pi"), { "extensions.permissionGatesEnabled": enabled });
				initSession(fixture);
				const ctx = makeCtx(fixture);
				ctx.hasUI = true;
				ctx.ui.confirm = async () => {
					assert.fail("Protected paths must never prompt");
				};
				ctx.ui.notify = () => {
					assert.fail("Protected paths must not notify");
				};
				for (const command of ["cat .env", "rm -rf /etc/passwd", "ls ./node_modules", "find . -type f"]) {
					assert.ok((await handleBashTools({ command }, ctx))?.block, command);
				}
				for (const tool of ["read", "write", "edit", "grep", "find"] as const) {
					for (const path of [".env", "/etc/passwd", "node_modules", "../outside.txt"]) {
						assert.ok((await handleFileIOTools(tool, { path }, ctx))?.block);
					}
				}
				for (const tool of ["write", "edit"] as const) {
					assert.ok((await handleFileIOTools(tool, { path: "node_modules/pkg/index.js" }, ctx))?.block);
				}
			} finally {
				cleanupFixture(fixture);
			}
		});
	}

	test("permission gates: global Pi settings apply when project omits the toggle", () => {
		const fixture = createFixture();
		try {
			writeSettings(agentDir, { "extensions.permissionGatesEnabled": "on" });
			initSession(fixture);
			assert.equal(state.permissionGatesEnabled, true);
			writeSettings(join(fixture, ".pi"), { "extensions.notificationsEnabled": false });
			initSession(fixture);
			assert.equal(state.permissionGatesEnabled, true);
			assert.equal(state.notificationsEnabled, false);
			writeSettings(join(fixture, ".pi"), { "extensions.permissionGatesEnabled": false });
			initSession(fixture);
			assert.equal(state.permissionGatesEnabled, false);
		} finally {
			cleanupFixture(fixture);
		}
	});

	for (const config of [{}, { "extensions.permissionGatesEnabled": 1 }, null, "{ malformed"]) {
		test(`permission gates: missing/invalid config resets an enabled session (${JSON.stringify(config)})`, () => {
			const fixture = createFixture();
			try {
				writeSettings(join(fixture, ".pi"), { "extensions.permissionGatesEnabled": true });
				initSession(fixture);
				assert.equal(state.permissionGatesEnabled, true);
				writeSettings(join(fixture, ".pi"), config);
				if (typeof config === "string") {
					writeFileSync(join(fixture, ".pi", "settings.json"), config);
				}
				initSession(fixture);
				assert.equal(state.permissionGatesEnabled, false);
				assert.equal(state.configLoaded, true);
				assert.equal(checkPathSecurity(join(fixture, ".env")), "BLOCK");
			} finally {
				cleanupFixture(fixture);
			}
		});
	}

	test("permission gates: malformed global settings default off", () => {
		const fixture = createFixture();
		try {
			state.permissionGatesEnabled = true;
			writeFileSync(join(agentDir, "settings.json"), "{ malformed");
			initSession(fixture);
			assert.equal(state.permissionGatesEnabled, false);
			assert.equal(state.configLoaded, true);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: no cwd-tree candidate allows find . scan", async () => {
		const fixture = createFixture();
		try {
			const parent = join(fixture, "parent");
			const project = join(parent, "project");
			mkdirSync(project, { recursive: true });
			mkdirSync(join(parent, "node_modules"));
			initSession(project);
			const result = await handleBashTools({ command: "find . -type f" }, makeCtx(project));
			assert.equal(result, undefined);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: parent-only allows find .; blocks root; allows package path", async () => {
		const fixture = createFixture();
		try {
			const parent = join(fixture, "parent");
			const project = join(parent, "project");
			mkdirSync(project, { recursive: true });
			const parentNodeModules = join(parent, "node_modules");
			mkdirSync(parentNodeModules);
			writeFileSync(join(parentNodeModules, "pkg.js"), "x");
			initSession(project);
			const scanResult = await handleBashTools({ command: "find . -type f" }, makeCtx(project));
			assert.equal(scanResult, undefined);
			const rootResult = await handleBashTools(
				{ command: `ls ${parentNodeModules}` },
				makeCtx(project)
			);
			assert.ok(rootResult?.block);
			const packageResult = await handleBashTools(
				{ command: `cat ${parentNodeModules}/pkg.js` },
				makeCtx(project)
			);
			assert.equal(packageResult, undefined);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: cwd node_modules blocks unexcluded find .", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			initSession(fixture);
			const result = await handleBashTools({ command: "find . -type f" }, makeCtx(fixture));
			assert.ok(result?.block);
			assert.match(result!.reason, /node_modules exclusion/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: immediate-child node_modules blocks unexcluded find .", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "packages", "node_modules"), { recursive: true });
			initSession(fixture);
			const result = await handleBashTools({ command: "find . -type f" }, makeCtx(fixture));
			assert.ok(result?.block);
			assert.match(result!.reason, /node_modules exclusion/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: unexcluded rg and grep -R are not blocked by pass 2", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			initSession(fixture);
			const ctx = makeCtx(fixture);
			assert.equal(
				await handleBashTools({ command: "rg TODO ." }, ctx),
				undefined
			);
			assert.equal(
				await handleBashTools({ command: "grep -R TODO ." }, ctx),
				undefined
			);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: find prune exclusion passes with cwd node_modules present", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			initSession(fixture);
			const ctx = makeCtx(fixture);
			assert.equal(
				await handleBashTools(
					{ command: "find . -path ./node_modules -prune -o -type f -print" },
					ctx
				),
				undefined
			);
			assert.equal(
				await handleBashTools(
					{ command: "find . -not -path './node_modules/*' -type f" },
					ctx
				),
				undefined
			);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: find prune of discovered child node_modules is allowed", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "packages", "node_modules"), { recursive: true });
			initSession(fixture);
			const ctx = makeCtx(fixture);
			assert.equal(
				await handleBashTools(
					{ command: "find . -path ./packages/node_modules -prune -o -type f -print" },
					ctx
				),
				undefined
			);
			assert.equal(
				await handleBashTools(
					{ command: "find . -not -path './packages/node_modules/*' -type f" },
					ctx
				),
				undefined
			);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: wrong ./node_modules prune does not satisfy child-only install", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "packages", "node_modules"), { recursive: true });
			initSession(fixture);
			const result = await handleBashTools(
				{ command: "find . -path ./node_modules -prune -o -type f -print" },
				makeCtx(fixture)
			);
			assert.ok(result?.block);
			assert.match(result!.reason, /node_modules exclusion/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: find ./ and trailing-slash cwd are gated by pass 2", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			initSession(fixture);
			const ctx = makeCtx(fixture);
			const dotSlash = await handleBashTools({ command: "find ./ -type f" }, ctx);
			assert.ok(dotSlash?.block);
			const absSlash = await handleBashTools(
				{ command: `find ${fixture}/ -type f` },
				ctx
			);
			assert.ok(absSlash?.block);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: fake exclusion does not unlock exact node_modules root bash", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			initSession(fixture);
			const ctx = makeCtx(fixture);
			const lsFake = await handleBashTools(
				{ command: "ls ./node_modules --exclude-dir=node_modules" },
				ctx
			);
			assert.ok(lsFake?.block);
			const catFake = await handleBashTools(
				{ command: "cat ./node_modules --exclude-dir=node_modules" },
				ctx
			);
			assert.ok(catFake?.block);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: content-search flags do not satisfy pass 2 find", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "packages", "node_modules"), { recursive: true });
			initSession(fixture);
			const ctx = makeCtx(fixture);
			const excludeDir = await handleBashTools(
				{ command: "find . --exclude-dir=node_modules -type f" },
				ctx
			);
			assert.ok(excludeDir?.block);
			assert.match(excludeDir!.reason, /node_modules exclusion/i);
			const globFlag = await handleBashTools(
				{ command: "find . --glob '!node_modules/**' -type f" },
				ctx
			);
			assert.ok(globFlag?.block);
			assert.match(globFlag!.reason, /node_modules exclusion/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: prune carve-out still blocks other blacklisted paths", async () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			initSession(fixture);
			const result = await handleBashTools(
				{
					command: "find . -path ./node_modules -prune -o -path ./.env -print",
				},
				makeCtx(fixture)
			);
			assert.ok(result?.block);
			assert.match(result!.reason, /blacklisted path/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: regex metacharacters in path block exact node_modules not backup", async () => {
		const fixture = createFixture();
		try {
			const project = join(fixture, "proj+ect");
			const nodeModules = join(project, "node_modules");
			mkdirSync(nodeModules, { recursive: true });
			mkdirSync(join(project, "node_modules_backup"), { recursive: true });
			writeFileSync(join(project, "node_modules_backup", "keep.txt"), "x");
			initSession(project);
			assert.equal(checkPathSecurity(nodeModules), "BLOCK");
			assert.notEqual(checkPathSecurity(join(nodeModules, "pkg.js")), "BLOCK");
			assert.notEqual(checkPathSecurity(join(project, "node_modules_backup", "keep.txt")), "BLOCK");
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: specific package read is allowed; exact root read is blocked", async () => {
		const fixture = createFixture();
		try {
			const nodeModules = join(fixture, "node_modules");
			mkdirSync(join(nodeModules, "@scope", "pkg"), { recursive: true });
			writeFileSync(join(nodeModules, "pkg.js"), "x");
			writeFileSync(join(nodeModules, "@scope", "pkg", "index.js"), "x");
			initSession(fixture);
			const ctx = makeCtx(fixture);
			const pkgResult = await handleFileIOTools(
				"read",
				{ path: join(nodeModules, "pkg.js") },
				ctx
			);
			assert.equal(pkgResult, undefined);
			const scopedResult = await handleFileIOTools(
				"read",
				{ path: join(nodeModules, "@scope", "pkg", "index.js") },
				ctx
			);
			assert.equal(scopedResult, undefined);
			/* grep/find are read-equivalent: package paths stay readable */
			const grepPkgResult = await handleFileIOTools(
				"grep",
				{ pattern: "x", path: join(nodeModules, "pkg.js") },
				ctx
			);
			assert.equal(grepPkgResult, undefined);
			const findPkgResult = await handleFileIOTools(
				"find",
				{ pattern: "*", path: join(nodeModules, "@scope", "pkg") },
				ctx
			);
			assert.equal(findPkgResult, undefined);
			const grepRootResult = await handleFileIOTools("grep", { pattern: "x", path: nodeModules }, ctx);
			assert.ok(grepRootResult?.block);
			const rootResult = await handleFileIOTools("read", { path: nodeModules }, ctx);
			assert.ok(rootResult?.block);
			assert.match(rootResult!.reason, /blacklisted/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: write and edit under package path remain blocked", async () => {
		const fixture = createFixture();
		try {
			const nodeModules = join(fixture, "node_modules");
			mkdirSync(nodeModules);
			writeFileSync(join(nodeModules, "pkg.js"), "x");
			initSession(fixture);
			const ctx = makeCtx(fixture);
			const writeResult = await handleFileIOTools(
				"write",
				{ path: join(nodeModules, "pkg.js") },
				ctx
			);
			assert.ok(writeResult?.block);
			assert.match(writeResult!.reason, /node_modules/i);
			const editResult = await handleFileIOTools(
				"edit",
				{ path: join(nodeModules, "pkg.js") },
				ctx
			);
			assert.ok(editResult?.block);
			assert.match(editResult!.reason, /node_modules/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: bash blocks exact node_modules root; allows specific package", async () => {
		const fixture = createFixture();
		try {
			const nodeModules = join(fixture, "node_modules");
			mkdirSync(join(nodeModules, "@scope"), { recursive: true });
			writeFileSync(join(nodeModules, "pkg.js"), "x");
			initSession(fixture);
			const ctx = makeCtx(fixture);
			const lsRoot = await handleBashTools({ command: "ls ./node_modules" }, ctx);
			assert.ok(lsRoot?.block);
			const findRoot = await handleBashTools({ command: "find ./node_modules -type f" }, ctx);
			assert.ok(findRoot?.block);
			const catPkg = await handleBashTools({ command: "cat node_modules/pkg.js" }, ctx);
			assert.equal(catPkg, undefined);
			const lsScoped = await handleBashTools({ command: "ls node_modules/@scope" }, ctx);
			assert.equal(lsScoped, undefined);
			const removeRoot = await handleBashTools({ command: "rm -rf ./node_modules" }, ctx);
			assert.equal(removeRoot, undefined);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: allows project-local rm in a command chain after cd", async () => {
		const fixture = createFixture();
		try {
			const project = join(fixture, "tekton-cicd");
			mkdirSync(join(project, "src", "k8s-io", "services"), { recursive: true });
			initSession(fixture);
			const command = [
				"cd tekton-cicd && rm -f src/k8s-io/services/k8s-io.service.js && npm run build 2>&1 && npm test -- k8s-io --runInBand",
				"2>&1 | grep -E \"(Error:|BadRequestException:|✓)\" | head -10",
			].join("\n");
			assert.equal(await handleBashTools({ command }, makeCtx(fixture)), undefined);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: project-local rm still blocks project .env", async () => {
		const fixture = createFixture();
		try {
			initSession(fixture);
			const result = await handleBashTools({ command: "rm -f .env" }, makeCtx(fixture));
			assert.ok(result?.block);
			assert.match(result!.reason, /blacklisted path/i);
		} finally {
			cleanupFixture(fixture);
		}
	});

	test("handler: malformed settings.json still installs discovery state", () => {
		const fixture = createFixture();
		try {
			mkdirSync(join(fixture, "node_modules"));
			mkdirSync(join(fixture, ".pi"), { recursive: true });
			writeFileSync(join(fixture, ".pi", "settings.json"), "{ invalid json");
			const expectedPath = resolve(join(fixture, "node_modules"));
			initSession(fixture);
			assert.equal(state.nodeModulesInCwdTree, true);
			assert.ok(state.nodeModulesPaths.some((p) => resolve(p) === expectedPath));
			assert.equal(state.configLoaded, true);
		} finally {
			cleanupFixture(fixture);
		}
	});
});
