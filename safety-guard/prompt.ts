import { state } from "./state";

/**
* Append security policy to the system prompt.
*/
export const appendSecurityPolicy = (systemPrompt: string): string => {
	const securityPolicy = `

--- SECURITY POLICY ---
## Security boundaries (enforced by safety-guard extension)

You must NEVER read, write, execute, or reference the contents of these paths.
Do not write scripts or code that access them either directly or indirectly:

${state.blockedPaths.map((path) => `- ${path} (including descendants; * matches within a path segment)`).join("\n")}
- Any .env or .env.* file anywhere in the project tree

If a task appears to require access to these paths, STOP and ask the user
to provide only the specific values needed rather than reading the files directly.
These restrictions are enforced at the tool level and cannot be bypassed.

Same applies to the read, update or print operations for the content of 
AWS secrets (AWS Secret Manager, KMS keys, Certificate keys) or content of
k8s secrets behind any flavor of Kubernetes cluster.
- SECURITY POLICY ---
`;
	return systemPrompt + securityPolicy;
};
