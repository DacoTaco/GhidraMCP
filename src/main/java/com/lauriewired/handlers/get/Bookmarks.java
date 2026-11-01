package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;

/**
 * Handler to list bookmarks, optionally filtered by type, category and address
 * range.
 */
public final class Bookmarks extends Handler {

    public Bookmarks(PluginTool tool) {
        super(tool);
    }

    public record BookmarkInformation(String Address, String Type, String Category, String Comment) {}

    /**
     * Lists bookmarks sorted by address.
     *
     * @param programName the program to work with
     * @param type optional bookmark type (Note, Info, Warning, Error, Analysis)
     * @param category optional category, must match exactly
     * @param start optional start of the address range
     * @param end optional end of the address range
     * @param offset the pagination offset
     * @param limit the maximum number of bookmarks to return
     * @return the matching bookmarks
     */
    @HttpRoute(method = HttpMethod.GET, path = "/bookmarks")
    @McpTool(name = "get_bookmarks", description = "Get bookmarks sorted by address, optionally filtered by type, category or address range.")
    public List<BookmarkInformation> listBookmarks(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "type", nullable = true, description = "Bookmark type") String type,
            @Param(name = "category", nullable = true, description = "Exact bookmark category.") String category,
            @Param(name = "offset", nullable = true) Integer offset,
            @Param(name = "limit", nullable = true) Integer limit) throws Exception {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        BookmarkManager bookmarkManager = program.getBookmarkManager();
        Iterator<Bookmark> iterator = bookmarkManager.getBookmarksIterator(program.getMinAddress(), true);

        List<BookmarkInformation> bookmarks = new ArrayList<>();
        while (iterator.hasNext()) {
            Bookmark bookmark = iterator.next();
            if (type != null && !type.isEmpty() && !bookmark.getTypeString().equalsIgnoreCase(type)) {
                continue;
            }
            if (category != null && !category.isEmpty() && !category.equals(bookmark.getCategory())) {
                continue;
            }

            bookmarks.add(new BookmarkInformation(bookmark.getAddress().toString(), bookmark.getTypeString(), bookmark.getCategory(), bookmark.getComment()));
        }

        return paginateList(bookmarks, offset == null ? 0 : offset, limit == null ? bookmarks.size() : limit);
    }
}
