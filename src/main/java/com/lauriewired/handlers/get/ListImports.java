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

/**
 * Handler for listing all external symbols (imports) in the current program.
 * Responds with a paginated list of imports in the format:
 * "symbolName -> symbolAddress".
 */
public final class ListImports extends Handler {
	/**
	 * Constructor for ListImports handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public ListImports(PluginTool tool) {
		super(tool);
	}

	/**
	 * Lists all external symbols (imports) in the current program, paginated.
	 *
	 * @param offset the starting index for pagination.
	 * @param limit  the maximum number of results to return.
	 * @return a string containing the paginated list of imports.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/imports")
    @McpTool(name = "list_imports", description = "List imported symbols in the program with pagination.")
    public String listImports(@Param(name = "program", nullable = true) String programName, @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		List<String> lines = new ArrayList<>();
		for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
			lines.add(symbol.getName() + " -> " + symbol.getAddress());
		}
		return paginateList(lines, offset, limit);
	}
}
