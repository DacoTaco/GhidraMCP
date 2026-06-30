package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Handler for listing memory segments in the current program.
 * Responds with a list of memory blocks, paginated by offset and limit.
 */
public final class ListSegments extends Handler {
	/**
	 * Constructor for ListSegments handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public ListSegments(PluginTool tool) {
		super(tool);
	}

	/**
	 * Lists memory segments in the current program, paginated by offset and limit.
	 *
	 * @param offset the starting index for pagination.
	 * @param limit  the maximum number of segments to return.
	 * @return a string representation of the memory segments, formatted for
	 *         pagination.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/segments")
    @McpTool(name = "list_segments", description = "List all memory segments in the program with pagination.")
	public String listSegments(@Param(name = "program", nullable = true) String programName, @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
		}
		return paginateList(lines, offset, limit);
	}
}
