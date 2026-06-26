package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.escapeString;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;

/**
 * Handler to list all defined strings in the current program
 * Supports pagination and filtering by string content
 */
public final class ListDefinedStrings extends Handler {
	/**
	 * Constructor for ListDefinedStrings handler
	 * 
	 * @param tool the PluginTool instance to use for accessing the current program
	 */
	public ListDefinedStrings(PluginTool tool) {
		super(tool);
	}

	/**
	 * List all defined strings in the program with their addresses
	 * 
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of results to return
	 * @param filter optional filter to apply to string values
	 * @return a formatted string containing the list of defined strings
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/strings")
    @McpTool(name = "list_strings", description = "List all defined strings in the program with their addresses.")
	public String listDefinedStrings(@Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit, 
									 @Param(name = "filter", nullable = true) String filter, @Param(name = "program", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
		List<String> lines = new ArrayList<>();
		DataIterator dataIt = program.getListing().getDefinedData(true);

		while (dataIt.hasNext()) {
			Data data = dataIt.next();

			if (data != null && isStringData(data)) {
				String value = data.getValue() != null ? data.getValue().toString() : "";

				if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
					String escapedValue = escapeString(value);
					lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
				}
			}
		}

		return paginateList(lines, offset, limit);
	}

	/**
	 * Check if the given data is a string type
	 * 
	 * @param data the Data object to check
	 * @return true if the data is a string type, false otherwise
	 */
	private boolean isStringData(Data data) {
		if (data == null)
			return false;

		DataType dt = data.getDataType();
		String typeName = dt.getName().toLowerCase();
		return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
	}
}
