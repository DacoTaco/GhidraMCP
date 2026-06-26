package com.lauriewired.handlers.comment;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.setCommentAtAddress;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CommentType;

/**
 * Handler for setting a comment in the disassembly at a specific address.
 * Expects POST request with parameters: address and comment.
 */
public final class SetDisassemblyComment extends Handler {
	/**
	 * Constructor for the SetDisassemblyComment handler.
	 *
	 * @param tool the Ghidra PluginTool instance
	 */
	public SetDisassemblyComment(PluginTool tool) {
		super(tool);
	}

	@HttpRoute(method=HttpMethod.POST, path = "/set_disassembly_comment")
	@McpTool(name="set_disassembly_comment", description="Set a comment for a given address in the function disassembly.")
	public String setDisassemblyCommentRoute(
		@Param(name = "address") String address,
		@Param(name = "comment") String comment,
		@Param(name = "program", nullable = true) String program
	) {
		return setDisassemblyComment(program, address, comment)
			? "Comment set successfully"
			: "Failed to set comment";
	}

	/**
	 * Sets a disassembly comment at the specified address.
	 *
	 * @param addressStr the address as a string
	 * @param comment    the comment to set
	 * @return true if the comment was set successfully, false otherwise
	 */
	private boolean setDisassemblyComment(String programName, String addressStr, String comment) {
		return setCommentAtAddress(tool, programName, addressStr, comment, CommentType.EOL, "Set disassembly comment");
	}
}
