package com.lauriewired.handlers.search;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Handler for searching functions by name in the current program.
 * Expects query parameters: query (search term), offset, limit.
 */
public final class SearchFunctions extends Handler {
	/**
	 * Constructor for SearchFunctions handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public SearchFunctions(PluginTool tool) {
		super(tool);
	}

	/**
	 * Searches for functions in the current program by name.
	 * Returns a paginated list of matching functions.
	 *
	 * @param searchTerm the term to search for in function names.
	 * @param offset     the pagination offset.
	 * @param limit      the maximum number of results to return.
	 * @return a string containing the results or an error message.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/searchFunctions")
    @McpTool(name = "search_functions_by_name", description = "Search for functions whose name contains the given substring.")
	public String searchFunctionsByName(@Param(name = "query") String searchTerm, @Param(name = "offset", nullable = true) Integer offset,
            							 @Param(name = "limit", nullable = true) Integer limit, @Param(name = "program", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		List<String> matches = new ArrayList<>();
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			String name = func.getName();
			// simple substring match
			if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
				matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
			}
		}

		Collections.sort(matches);

		if (matches.isEmpty()) {
			return "No functions matching '" + searchTerm + "'";
		}
		return paginateList(matches, offset, limit);
	}
}
