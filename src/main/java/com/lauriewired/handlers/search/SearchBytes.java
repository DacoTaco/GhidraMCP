package com.lauriewired.handlers.search;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.decodeHex;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Handler for searching for byte sequences in the current program's memory.
 * Expects a hex string of bytes to search for, with optional pagination
 * parameters.
 */
public final class SearchBytes extends Handler {
	/**
	 * Constructor for the SearchBytes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public SearchBytes(PluginTool tool) {
		super(tool);
	}

	/**
	 * Searches for the specified byte sequence in the current program's memory.
	 * 
	 * @param bytesHex The hex string of bytes to search for.
	 * @param offset   The starting index for pagination.
	 * @param limit    The maximum number of results to return.
	 * @return A string containing the search results, formatted for pagination.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/search_bytes")
    @McpTool(name = "search_bytes", description = "Search the whole program for a specific byte sequence.")
	public String searchBytes(@Param(name = "bytes", description = "Byte sequence encoded as a hex string (e.g. DEADBEEF or DE AD BE EF).") String bytesHex, @Param(name = "program", nullable = true) String programName, 
							  @Param(name = "offset", nullable = true, description = "Pagination offset for results (default: 0).") Integer offset, @Param(name = "limit", nullable = true, description = "Maximum number of hit addresses to return (default: 100).") Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		byte[] needle;
		try {
			needle = decodeHex(bytesHex);
		} catch (IllegalArgumentException e) {
			return "Invalid hex string: " + bytesHex;
		}

		Memory mem = program.getMemory();
		List<String> hits = new ArrayList<>();

		Address cur = mem.getMinAddress();
		while (cur != null && hits.size() < offset + limit) {
			Address found = mem.findBytes(cur, needle, null, true, TaskMonitorAdapter.DUMMY);
			if (found == null)
				break;
			hits.add(found.toString());

			cur = found.add(1);
		}

		return paginateList(hits, offset, limit);
	}
}