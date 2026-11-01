package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;

/**
 * Handler for adding and removing bookmarks.
 */
public final class Bookmarks extends Handler {

    /**
     * Constructor for Bookmarks.
     *
     * @param tool the plugin tool
     */
    public Bookmarks(PluginTool tool) {
        super(tool);
    }

    @McpTool(name = "add_bookmark", description = "Creates a bookmark at the specified address. Fails if one of the same type exists.")
    @HttpRoute(method = HttpMethod.POST, path = "/bookmark")
    public void AddBookmark(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName, @Param(name = "address", description = "The address to create the bookmark at.") String addressStr,
            @Param(name = "category", description = "The category of the bookmark.") String category, @Param(name = "comment", description = "The comment for the bookmark.") String comment,
            @Param(name = "type", nullable = true, description = "Bookmark type (default: Note). Available types: Note, Info, Warning, Error, Analysis.") String type) throws Exception {
        final String resolvedType = (type == null) ? "Note" : type;
        Program currentProgram = getProgramByName(programName);
        if (currentProgram == null) {
            throw new Exception("No active program");
        }

        Address address = AddressUtils.parseAddress(currentProgram, addressStr);
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        if (bookmarkManager.getBookmarks(address, resolvedType).length > 0) {
            throw new IllegalArgumentException("A " + resolvedType + " bookmark already exists at " + address);
        }

        // a Runnable can't throw checked exceptions, so the error is carried out of the Swing thread
        final AtomicReference<Exception> error = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int transactionID = currentProgram.startTransaction("Add Bookmark");
                boolean success = false;
                try {
                    bookmarkManager.setBookmark(address, resolvedType, category, comment);
                    success = true;
                } catch (Exception e) {
                    error.set(e);
                } finally {
                    currentProgram.endTransaction(transactionID, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            throw new Exception("Failed to execute add bookmark on Swing thread: " + e.getMessage(), e);
        }

        if (error.get() != null) {
            throw error.get();
        }
    }

    /**
     * Removes the bookmarks at an address that match the optional type and
     * category.
     *
     * @throws Exception when no bookmark matched or they could not be removed
     */
    @HttpRoute(method = HttpMethod.DELETE, path = "/bookmark")
    @McpTool(name = "remove_bookmark", description = "Remove the bookmarks at an address, optionally only a given type or category.")
    public void RemoveBookmark(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address", description = "Address, in hex.") String address,
            @Param(name = "type", nullable = true, description = "Bookmark type, e.g. Note.") String type,
            @Param(name = "category", nullable = true, description = "Exact bookmark category.") String category) throws Exception {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        Address addr = AddressUtils.parseAddress(program, address);
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        List<Bookmark> matches = Arrays.stream(bookmarkManager.getBookmarks(addr))
                .filter(b -> type == null || type.isEmpty() || b.getTypeString().equalsIgnoreCase(type))
                .filter(b -> category == null || category.isEmpty() || category.equals(b.getCategory()))
                .toList();
        if (matches.isEmpty()) {
            throw new IllegalArgumentException("No matching bookmarks at " + addr);
        }

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove bookmark");
                boolean success = false;
                try {
                    for (Bookmark bookmark : matches) {
                        bookmarkManager.removeBookmark(bookmark);
                    }
                    success = true;
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            throw new Exception("Failed to execute remove bookmark on Swing thread: " + e.getMessage(), e);
        }
    }
}
