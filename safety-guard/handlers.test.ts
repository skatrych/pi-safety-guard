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
import { handleBashTools, handleFileIOTools, onSessionStart } from "./handlers";
import { state } from "./state";
import { BLACKLIST, WHITELIST } from "./constants";
import { checkPathSecurity } from "./security";

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
	allowedPaths: string[];
	notificationsEnabled: boolean;
	configLoaded: boolean;
	nodeModulesPaths: string[];
	nodeModulesInCwdTree: boolean;
	blacklist: RegExp[];
	whitelist: RegExp[];
};

let stateSnapshot: StateSnapshot;

const captureState = (): StateSnapshot => ({
	allowedPaths: [...state.allowedPaths],
	notificationsEnabled: state.notificationsEnabled,
	configLoaded: state.configLoaded,
	nodeModulesPaths: [...state.nodeModulesPaths],
	nodeModulesInCwdTree: state.nodeModulesInCwdTree,
	blacklist: [...BLACKLIST],
	whitelist: [...WHITELIST],
});

const restoreState = (snap: StateSnapshot): void => {
	state.allowedPaths = snap.allowedPaths;
	state.notificationsEnabled = snap.notificationsEnabled;
	state.configLoaded = snap.configLoaded;
	state.nodeModulesPaths = snap.nodeModulesPaths;
	state.nodeModulesInCwdTree = snap.nodeModulesInCwdTree;
	BLACKLIST.length = 0;
	BLACKLIST.push(...snap.blacklist);
	WHITELIST.length = 0;
	WHITELIST.push(...snap.whitelist);
};

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
	beforeEach(() => {
		stateSnapshot = captureState();
	});

	afterEach(() => {
		restoreState(stateSnapshot);
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
