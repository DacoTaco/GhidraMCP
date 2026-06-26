package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/**
 * Handler for listing namespaces in the current program.
 * 
 * Example usage:
 * GET /namespaces?offset=0&limit=100
 */
public final class ListNamespaces extends Handler {
	/**
	 * Constructor for the ListNamespaces handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public ListNamespaces(PluginTool tool) {
		super(tool);
	}

	/**
	 * Lists namespaces in the current program, paginated by offset and limit.
	 *
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of namespaces to return
	 * @return a string representation of the paginated list of namespaces
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/namespaces")
    @McpTool(name = "list_namespaces", description = "List all non-global namespaces in the program with pagination.")
	public String listNamespaces(@Param(name = "program", nullable = true) String programName, @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		Set<String> namespaces = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !(ns instanceof GlobalNamespace)) {
				namespaces.add(ns.getName());
			}
		}
		List<String> sorted = new ArrayList<>(namespaces);
		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}
}
