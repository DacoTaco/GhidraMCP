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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Handler to get all function names in the current program.
 * 
 * Example usage: GET /methods?offset=0&limit=100
 */
public final class GetAllFunctionNames extends Handler {
	/**
	 * Constructor for the GetAllFunctionNames handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public GetAllFunctionNames(PluginTool tool) {
		super(tool);
	}

	/**
	 * Generates a paginated response containing all function names in the current
	 * program.
	 *
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of function names to return
	 * @return a string containing the paginated list of function names
	 */
	@HttpRoute(method=HttpMethod.GET, path="/methods")
	@McpTool(name = "list_methods", description = "List all function names in the program with pagination.")
	public String generateResponse(@Param(name="program", nullable=true) String programName, @Param(name="offset", nullable=true) Integer offset, @Param(name="limit", nullable=true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		if(offset == null)
			offset = 0;

		if(limit == null)
			limit = 100;

		List<String> names = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			names.add(f.getName());
		}
		return paginateList(names, offset, limit);
	}
}
