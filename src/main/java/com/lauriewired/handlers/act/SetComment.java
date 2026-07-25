package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
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
	) {
		return SetComment(program, address, null, comment);
	}

	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.POST, path = "/set_disassembly_comment")
	public String setDisassemblyCommentRoute(
		@Param(name = "address") String address,
		@Param(name = "comment") String comment,
		@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String program
	) {
		return SetComment(program, address, true, comment);
	}

	/**
	 * Sets a decompiler comment at the specified address
	 * 
	 * @param addressStr The address as a string where the comment should be set
	 * @param comment    The comment to set
	 * @return true if the comment was set successfully, false otherwise
	 */
	@HttpRoute(method=HttpMethod.POST, path = "/set_comment")
	@McpTool(name="set_comment", description="Set a comment for a given address in the function pseudocode or disassembly.")
	public String SetComment(
		@Param(name = "address") String address,
		@Param(name = "comment") String comment,
		@Param(name = "disassemblyComment", nullable=true, description="Optional, only to be set if you know for sure you want to set a disassembly comment") Boolean disassemblyComment,
		@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName
	) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "Program not found";

		if (address == null || address.isEmpty() || comment == null)
			return "address and comment must be provided";

		AtomicBoolean success = new AtomicBoolean(false);
		disassemblyComment = (disassemblyComment != null) ? disassemblyComment : false;
		String transactionName = disassemblyComment ? "Set disassembly comment" : "Set decompiler comment";
		CommentType commentType = disassemblyComment ? CommentType.EOL : CommentType.PRE; // Default to PRE for decompiler comments

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction(transactionName);
				try {
					Address addr = program.getAddressFactory().getAddress(address);
					program.getListing().setComment(addr, commentType, comment);
					success.set(true);
				} catch (Exception e) {
					Msg.error(SetComment.class, "Error setting " + transactionName.toLowerCase(), e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(SetComment.class, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
		}

		return success.get()
			? "Comment set successfully"
			: "Failed to set comment";
	}
}
