package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/**
 * Handler to get all class names in the current program.
 * Supports pagination via 'offset' and 'limit' query parameters.
 */
public final class GetAllClassNames extends Handler {
	/**
	 * Constructor for the GetAllClassNames handler.
	 *
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public GetAllClassNames(PluginTool tool) {
		super(tool);
	}

	/**
	 * Generates a response containing all class names in the current program,
	 * with optional pagination.
	 *
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of class names to return.
	 * @return A string containing the paginated list of class names.
	 */
	@HttpRoute(method=HttpMethod.GET, path="/classes")
	@McpTool(name = "list_classes", description = "List all class names in the current program with optional pagination.")
	public List<String> generateResponse(@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName, 
								   @Param(name="offset", description="The starting index for pagination.", nullable=true) Integer offset, 
								   @Param(name="limit", description="The maximum number of class names to return.", nullable=true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return List.of((programName == null || programName.isEmpty()) ? "No program loaded" : "No Program with name '" + programName + "is loaded");

		if(offset == null)
			offset = 0;

		if(limit == null)
			limit = 100;

		Set<String> classNames = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !ns.isGlobal()) {
				classNames.add(ns.getName());
			}
		}
		// Convert set to list for pagination
		List<String> sorted = new ArrayList<>(classNames);
		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}
}
