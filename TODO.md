# TODO List

## Open Tasks

- [x] 1: Implement monitoring for 'edit' tool calls
- [x] 2: Add ~/.kube/ to hardcoded blacklist to match prompt policy
- [x] 3: Fix project-specific blacklist accumulation across sessions
- [x] 4: Implement tilde expansion for 'read' and 'write' tool paths
- [x] 5: Improve bash path extraction to detect bare filenames
- [ ] 6: Align prompt policy with runtime reality regarding bypassability
- [ ] 7: Audit and add monitoring for other custom/future tools
- [ ] 8: Ensure consistent resolution of tilde-expanded paths in all tools
- [ ] 9: Review and improve bash command sanitization patterns
- [ ] 10: Enhance logging for blocked/rejected operations
- [x] 11: Strictly enforce BLACKLIST policy by disabling interactive user overrides
- [ ] 12: Detect blacklisted paths in bash pipes and output redirects (e.g., `> .env`, `| tee .env`)
- [ ] 13: Prevent access to files outside the current project directory (directory traversal)


## TASK DESCRIPTION

- **3**: Currently, project-specific blacklist entries (like `.env` paths) are appended to a mutable global list during `session_start`. This causes the list to grow indefinitely across multiple sessions in the same process. It should be cleared or reset per session to ensure only relevant paths are blacklisted.
- **4**: While tilde expansion (e.g., `~/path`) is handled during bash command path extraction, it is currently missing for `read` and `write` tool inputs. This means paths starting with `~` might bypass security checks or fail to resolve correctly.
- **5**: The current bash parser ignores bare words (e.g., `config.json`) to reduce false positives. This creates a security gap where sensitive files referenced without explicit path prefixes (like `./` or `/`) bypass path-based blacklist checks.
- **11**: Enforce a strict blocking policy for any operations targeting blacklisted paths, removing the option for user override. Operations involving 'dangerous' bash commands that do not target blacklisted paths should retain the interactive user approval flow. This ensures absolute protection for sensitive paths while maintaining flexibility for potentially risky but necessary shell operations.
- **13**: Implement a check to prevent the agent from accessing files outside the current working directory or the project root. This should mitigate directory traversal attacks where the agent tries to read or write files in neighboring repositories or system directories (e.g., using `../`).




