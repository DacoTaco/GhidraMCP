package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Handler for listing all exports in the current program.
 * Exports are symbols that are external entry points, typically functions.
 * 
 * Example usage:
 * GET /exports?offset=0&limit=100
 */
public final class ListExports extends Handler {
	/**
	 * Constructor for ListExports handler.
	 * 
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public ListExports(PluginTool tool) {
		super(tool);
	}

	/**
	 * Lists all exports in the current program, paginated by offset and limit.
	 * 
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of exports to return
	 * @return a string representation of the exports, formatted for pagination
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/exports")
    @McpTool(name = "list_exports", description = "List exported functions/symbols with pagination.")
	public String listExports(@Param(name = "program", nullable = true) String programName, @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		SymbolTable table = program.getSymbolTable();
		SymbolIterator it = table.getAllSymbols(true);

		List<String> lines = new ArrayList<>();
		while (it.hasNext()) {
			Symbol s = it.next();
			// On older Ghidra, "export" is recognized via isExternalEntryPoint()
			if (s.isExternalEntryPoint()) {
				lines.add(s.getName() + " -> " + s.getAddress());
			}
		}
		return paginateList(lines, offset, limit);
	}
}
