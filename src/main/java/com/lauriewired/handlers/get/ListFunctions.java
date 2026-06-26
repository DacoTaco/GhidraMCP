package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Handler to list all functions in the current program.
 * Responds with a list of function names and their entry points.
 */
public final class ListFunctions extends Handler {

    public ListFunctions(PluginTool tool) {
        super(tool);
    }

	/**
	 * Lists all functions in the current program.
	 *
	 * @return a string containing the names and entry points of all functions
	 */
	@HttpRoute(method=HttpMethod.GET, path = "/list_functions")
	@McpTool(name="list_functions", description="List all functions in the database.")
	public String listFunctions(@Param(name="program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded - " + programName + " was not found";

		StringBuilder result = new StringBuilder();
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			result.append(String.format("%s at %s\n",
					func.getName(),
					func.getEntryPoint()));
		}

		return result.toString();
	}
}
