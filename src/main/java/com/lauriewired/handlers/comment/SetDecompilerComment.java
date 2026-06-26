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
 * Handler for setting a decompiler comment in Ghidra
 * This handler processes HTTP requests to set comments on decompiled code
 */
public final class SetDecompilerComment extends Handler {
	/**
	 * Constructor for the SetDecompilerComment handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public SetDecompilerComment(PluginTool tool) {
		super(tool);
	}

	@HttpRoute(method=HttpMethod.POST, path = "/set_decompiler_comment")
	@McpTool(name="set_decompiler_comment", description="Set a comment for a given address in the function pseudocode.")
	public String setDecompilerCommentRoute(
		@Param(name = "address") String address,
		@Param(name = "comment") String comment,
		@Param(name = "program", nullable = true) String program
	) {
		return setDecompilerComment(program, address, comment)
			? "Comment set successfully"
			: "Failed to set comment";
	}

	/**
	 * Sets a decompiler comment at the specified address
	 * 
	 * @param addressStr The address as a string where the comment should be set
	 * @param comment    The comment to set
	 * @return true if the comment was set successfully, false otherwise
	 */
	private boolean setDecompilerComment(String programName,String addressStr, String comment) {
		return setCommentAtAddress(tool, programName, addressStr, comment, CommentType.PRE, "Set decompiler comment");
	}
}
