import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { handleToolCall, onSessionStart } from "./handlers";

export default function (pi: ExtensionAPI) {
	// Register session start handler
	pi.on("session_start", onSessionStart);

	// Register consolidated tool_call handler
	pi.on("tool_call", handleToolCall);
}
