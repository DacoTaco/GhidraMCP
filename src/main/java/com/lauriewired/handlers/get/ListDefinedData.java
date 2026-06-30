package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.escapeNonAscii;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Handler for listing defined data in the current program.
 * 
 * Example usage: GET /data?offset=0&limit=100
 */
public final class ListDefinedData extends Handler {
	/**
	 * Constructs a new ListDefinedData handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public ListDefinedData(PluginTool tool) {
		super(tool);
	}

	/**
	 * Lists defined data in the current program, paginated by offset and limit.
	 * 
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of items to return.
	 * @return A string representation of the defined data, formatted for display.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/data")
    @McpTool(name="list_data_items", description = "List defined data labels and their values with pagination.")
	public String listDefinedData(@Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit, @Param(name = "program", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;

		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
			while (it.hasNext()) {
				Data data = it.next();
				if (block.contains(data.getAddress())) {
					String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
					String valRepr = data.getDefaultValueRepresentation();
					lines.add(String.format("%s: %s = %s",
							data.getAddress(),
							escapeNonAscii(label),
							escapeNonAscii(valRepr)));
				}
			}
		}
		return paginateList(lines, offset, limit);
	}
}
