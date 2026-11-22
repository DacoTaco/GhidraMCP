package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import com.lauriewired.util.GhidraUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
/**
 * Handler for setting a decompiler comment in Ghidra
 * This handler processes HTTP requests to set comments on decompiled code
 */
public final class SetComment extends Handler {
	/**
	 * Constructor for the SetComment handler
	 * 
	 * @param tool The Ghidra PluginTool instance
	 */
	public SetComment(PluginTool tool) {
		super(tool);
	}

	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.POST, path = "/set_decompiler_comment")
	public String SetDecompilerCommentRoute(
		@Param(name = "address") String address,
		@Param(name = "comment") String comment,
		@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String program
	) throws Exception {
		return SetComment(address, comment, null, null, program);
	}

	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.POST, path = "/set_disassembly_comment")
	public String setDisassemblyCommentRoute(
		@Param(name = "address") String address,
		@Param(name = "comment") String comment,
		@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String program
	) throws Exception {
		return SetComment(address, comment, true, null, program);
	}

	/**
	 * Sets a decompiler comment at the specified address
	 * 
	 * @param addressStr The address as a string where the comment should be set
	 * @param comment    The comment to set, empty removes the comment
	 * @param commentType Optional comment type, overrides disassemblyComment
	 * @return true if the comment was set successfully, false otherwise
	 */
	@HttpRoute(method=HttpMethod.POST, path = "/set_comment")
	@McpTool(name="set_comment", description="Set or remove a comment for a given address in the function pseudocode or disassembly. An empty comment removes it.")
	public String SetComment(
		@Param(name = "address") String address,
		@Param(name = "comment", nullable=true, description="The comment. Empty removes the comment.") String comment,
		@Param(name = "disassemblyComment", nullable=true, description="Optional, only to be set if you know for sure you want to set a disassembly comment") Boolean disassemblyComment,
		@Param(name = "commentType", nullable=true, description="Optional comment type: PRE, EOL, PLATE, POST or REPEATABLE. Overrides disassemblyComment.") CommentType commentType,
		@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName
	) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("Program not found");

		if (address == null || address.isEmpty())
			throw new IllegalArgumentException("address must be provided");

		disassemblyComment = (disassemblyComment != null) ? disassemblyComment : false;
		CommentType type = (commentType != null)
			? commentType
			: disassemblyComment ? CommentType.EOL : CommentType.PRE; // Default to PRE for decompiler comments

		// an empty comment removes the comment
		final String text = (comment == null || comment.isEmpty()) ? null : comment;
		String transactionName = (text == null ? "Remove " : "Set ") + type.name().toLowerCase() + " comment";

		GhidraUtils.RunTransaction(program, transactionName, () -> {
			Address addr = AddressUtils.parseAddress(program, address);
			program.getListing().setComment(addr, type, text);
			return null;
		});

		return text == null ? "Comment removed" : "Comment set successfully";
	}
}
