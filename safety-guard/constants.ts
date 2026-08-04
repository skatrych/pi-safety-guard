import { homedir } from "node:os";

// Cached home directory for consistent path expansion (no hardcoded paths)
export const HOME_DIR = homedir();

/**
 * Escape a string for use as a RegExp literal.
 * Prevents special characters in file paths (e.g. dots, parens, username with +)
 * from being misinterpreted as regex metacharacters in BLACKLIST/WHITELIST entries.
 */
export function escapeRegExp(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Deletion operations that may be allowed when their targets are strictly inside
// the project. Other dangerous operations still require their normal safeguards.
export const projectLocalDeletionPatterns = [
	/\brm\s+(-[rRfFoOpPsuUz]*[rRfFoOpPsuUz]*)/i,
	/\brm\s+--recursive\b/i,
	/\brm\s+--force\b/i,
	/\bunlink\s+/i,
	/\brmdir\s+/i,
	/\brm\s+\*[rRfFoPoU]*\b/i,
	/\brm\s+\*\/\*[rRfFoPoU]*\b/i,
	/\bshred\s+/i,
];

// ===== PRIORITY 1: DevOps Infrastructure Patterns =====
export const dangerousBashPatterns = [
	...projectLocalDeletionPatterns,
	/\bfind\s+.*-exec\s+rm\s+/i, // find ... -exec rm
	/\bfind\s+.*-exec\s+-\w+r/i, // find ... -exec rm -rf
	/\bxargs\s+rm\b/i, // xargs rm (narrowed: only xargs rm, not all xargs)
	/\btruncate\s+/i, // truncate
	/\bdd\s+(if|of|bs|count|seek|skip)=/i, // dd with actual disk args (narrowed: not bare `dd`)
	/\bmv\s+-f\b/i, // mv -f
	/\bchmod\s+777\b/i, // chmod 777
	/\bchmod\s+[0-7]*7[0-7]*7/i, // chmod 777 variant
	/(\bcurl|\bwget)\s+.*\|.*sh\b/i, // curl|sh, wget|sh
	/\bcurl.*-.*\|.*sh/i, // curl with flags pipe to sh
	/\bbash\s+-c\s+.*\brm\b/i, // bash -c "rm"
	/\bbash\s+-c\s+.*rm\s+-[rRfF]/i, // bash -c "rm -r"
	/\bsudo\s+.*\brm\s+-[rRfF]/i, // sudo rm -rf
	/\bfind\s+.*-delete\b/i, // find ... -delete
	/\bexec\s+rm\s+/i, // exec rm
	/\bwipefs\s+/i, // wipefs (wipe filesystem)
	/:\s*\(\s*\)\s*\{.*:\s*\|.*.*&.*\}/, // fork bomb: :(){ :|:& };:
	/>\s*\/dev\/(sd[a-z]|nvme\d|hd[a-z])\b/i, // redirect to raw disk device

	// Kubernetes / kubectl
	/\bkubectl\s+delete\s+/i, // kubectl delete
	/\bkubectl\s+delete\s+--all\b/i, // kubectl delete --all
	/\bkubectl\s+apply\s+.*--prune/i, // kubectl apply --prune
	// Helm
	/\bhelm\s+uninstall\s+/i, // helm uninstall
	// Terraform / OpenTofu
	/\btofu\s+destroy\b/i, // tofu destroy
	/\bterraform\s+destroy\b/i, // terraform destroy
	/\btofu\s+state\s+rm\b/i, // tofu state rm
	/\btofu\s+apply\s+.*-auto-app/i, // tofu apply -auto-approve
	// Docker
	/\bdocker\s+rm\s+-f/i, // docker rm -f
	/\bdocker\s+system\s+prune\b/i, // docker system prune
	/\bdocker\s+rmi\s+-f/i, // docker rmi -f
	// AWS
	/\baws\s+\w+\s+delete\b/i, // aws ec2 terminate, s3 rm
	/\baws\s+s3\s+rm\s+.*--recursive/i, // s3 rm --recursive (fixed: was -recursive)
	// Git
	/\bgit\s+push\s+-f/i, // git push -f
	/\bgit\s+push\s+--force/i, // git push --force
	/\bgit\s+reset\s+--hard\b/i, // git reset --hard
	/\bgit\s+clean\s+-fd/i, // git clean -fdx
	/\bgit\s+branch\s+-D/i, // git branch -D
];

/**
 * Token skip list for bash command parsing.
 */
export const COMMAND_NAME_TOKENS = new Set([
	"cat", "bat", "less", "more", "head", "tail", "tac", // file content
	"ls", "ll", "la", "dir", "exa", "eza", "lsd", // directory listing
	"find", "locate", "fd", // file discovery
	"grep", "rg", "ag", "ack", // content search
	"stat", "file", "strings", "xxd", "hexdump", "od", // file inspection
	"diff", "cmp", "comm", // comparison (can leak content)
	"cp", // copy (reads source)
	"tar", "zip", "gzip", "bzip2", "xz", "zstd", // archiving (reads source)
	"scp", "rsync", // remote copy (reads source)
	"open", "xdg-open", // open (reveals path)
	"nano", "vim", "vi", "nvim", "emacs", "code", // editors
	"python", "python3", "ruby", "perl", "node", // interpreters that may read files
	"awk", "sed", "cut", "sort", "uniq", "wc", // text processing that reads stdin/file
	"jq", "yq", "xmllint", // data query tools
	"sqlite3", "psql", "mysql", // DB CLI (may read credential files)
	"env", "printenv", "export", // environment (may reveal secrets in env)
	"source", // source a file (executes it!)
	"sh", "bash", "zsh", "fish", // shells with file args
	"base64", // encoding that reads stdin/file
	"curl", "wget", // can POST file contents
	"pbcopy", "xclip", "xsel", // clipboard (exfiltrates content)
]);

// ===== PATH SECURITY MODEL: WHITELIST / BLACKLIST =====
// BLACKLIST has HIGHEST priority - evaluated FIRST
// WHITELIST has LOWER priority - evaluated SECOND

// Blacklisted paths (credentials/confidential data)
export const BLACKLIST: RegExp[] = [
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.pi/agent/auth\\.json`), // Models credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.pi/agent/sessions(?:/|$)`), // Agent session transcripts
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.claude/sessions(?:/|$)`), // Claude session transcripts
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.ssh/`), // SSH credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.cursor/`), // Cursor IDE credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.gnupg/`), // GPG credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/Library/Keychains/`), // macOS Keychain
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.aws/credentials`), // AWS credentials file
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.kube/`), // Kubernetes credentials
	new RegExp(`^${escapeRegExp(HOME_DIR)}/Pictures/Photos Library\\.photoslibrary/`), // Photos library (confidential)
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.env$`), // ~/.env (home-level secrets)
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.env\\.`), // ~/.env.* (e.g. ~/.env.local)
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.gitconfig$`), // ~/.gitconfig (name, email, tokens)
	new RegExp(`^/etc/`), // System configs
	new RegExp(`^/usr/`), // System directories
	new RegExp(`^/System/`), // macOS System
];

// Whitelisted paths (safe explicit directories)
export const WHITELIST: RegExp[] = [
	new RegExp(`^${escapeRegExp(HOME_DIR)}/\\.pi(?:/|$)`), // Pi config directory
	new RegExp(`^/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/`), // Pi agent code
	new RegExp(`^/tmp(?:/|$)`), // /tmp directory
];
