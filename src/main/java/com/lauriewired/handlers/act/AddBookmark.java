package com.lauriewired.handlers.act;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;


/**
 * Handler for POST requests to add a bookmark at a specific address.
 */
public class AddBookmark extends Handler {
	/**
	 * Constructor for AddBookmark.
	 *
	 * @param tool the plugin tool
	 */
	public AddBookmark(PluginTool tool) {
		super(tool);
	}

    @McpTool(
        name = "add_bookmark",
        description = """
            Creates a bookmark at the specified address.
            If a bookmark of the same type already exists, it will be replaced.
            """
    )
    @HttpRoute(method = HttpMethod.POST, path = "/add_bookmark")
	public String addBookmark(@Param(name="program", nullable=true) String programName, @Param(name="address", description="The address to create the bookmark at.") String addressStr, 
                               @Param(name="category", description="The category of the bookmark.") String category, @Param(name="comment", description="The comment for the bookmark.") String comment,
                               @Param(name="type", nullable=true, description="Bookmark type (default: Note). Available types: Note, Info, Warning, Error, Analysis.") String type) {
		final String resolvedType = (type == null) ? "Note" : type;
		Program currentProgram = getProgramByName(programName);
		if (currentProgram == null)
			return "No active program";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int transactionID = currentProgram.startTransaction("Add Bookmark");
				boolean success = false;
				try {
					Address address = currentProgram.getAddressFactory().getAddress(addressStr);
					BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
					bookmarkManager.setBookmark(address, resolvedType, category, comment);
					result.set("Bookmark created successfully at " + addressStr);
					success = true;
				} catch (Exception e) {
					result.set("Error processing request: " + e.getMessage());
				} finally {
					currentProgram.endTransaction(transactionID, success);
				}
			});
		} catch (Exception e) {
			return "Error processing request: " + e.getMessage();
		}
		return result.get();
	}
}
