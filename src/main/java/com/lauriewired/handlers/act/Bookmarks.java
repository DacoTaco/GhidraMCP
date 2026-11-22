package com.lauriewired.handlers.act;

import java.util.Arrays;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import com.lauriewired.util.GhidraUtils;

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

        GhidraUtils.RunTransaction(currentProgram, "Add Bookmark", () -> {
            bookmarkManager.setBookmark(address, resolvedType, category, comment);
            return null;
        });
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

        GhidraUtils.RunTransaction(program, "Remove bookmark", () -> {
            for (Bookmark bookmark : matches) {
                bookmarkManager.removeBookmark(bookmark);
            }
            return null;
        });
    }
}
