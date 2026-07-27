import { readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export type NodeModulesDiscovery = {
	paths: string[];
	nodeModulesInCwdTree: boolean;
};

const isDirectory = (path: string): boolean => {
	try {
		return statSync(path).isDirectory();
	} catch {
		return false;
	}
};

const immediateDirectories = (cwd: string): string[] => {
	try {
		return readdirSync(cwd, { withFileTypes: true })
			.filter((entry) => entry.isDirectory() && entry.name !== "node_modules")
			.map((entry) => entry.name);
	} catch {
		return [];
	}
};

export const discoverNodeModules = (cwd: string): NodeModulesDiscovery => {
	const absoluteCwd = resolve(cwd);
	const parent = dirname(absoluteCwd);
	const paths: string[] = [];
	let nodeModulesInCwdTree = false;

	const cwdCandidate = join(absoluteCwd, "node_modules");
	if (isDirectory(cwdCandidate)) {
		paths.push(cwdCandidate);
		nodeModulesInCwdTree = true;
	}

	if (parent !== absoluteCwd) {
		const parentCandidate = join(parent, "node_modules");
		if (isDirectory(parentCandidate)) {
			paths.push(parentCandidate);
		}
	}

	for (const childName of immediateDirectories(absoluteCwd)) {
		const childCandidate = join(absoluteCwd, childName, "node_modules");
		if (isDirectory(childCandidate)) {
			paths.push(childCandidate);
			nodeModulesInCwdTree = true;
		}
	}

	return { paths, nodeModulesInCwdTree };
};
