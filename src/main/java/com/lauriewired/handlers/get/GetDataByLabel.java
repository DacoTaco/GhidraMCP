package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.escapeString;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Handler to retrieve data associated with a specific label in the current
 * program.
 * It responds with the address and value of the data defined at that label.
 */
public final class GetDataByLabel extends Handler {
	/**
	 * Constructor for the GetDataByLabel handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public GetDataByLabel(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves data associated with the specified label in the current program.
	 * 
	 * @param label The label to search for in the current program.
	 * @return A string containing the address and value of the data defined at that
	 *         label,
	 *         or an error message if the label is not found or no program is
	 *         loaded.
	 */
	@HttpRoute(method=HttpMethod.GET, path="/get_data_by_label")
    @McpTool(name="get_data_by_label", description = "Get information about a data label in the current program")
    public String handle(@Param(name="program", nullable=true, description="Program name to query.") String programName, @Param(name="label", description="Exact symbol / label name.") String label){
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		if (label == null || label.isEmpty())
			return "Label is required";

		SymbolTable st = program.getSymbolTable();
		SymbolIterator it = st.getSymbols(label);
		if (!it.hasNext())
			return "Label not found: " + label;

		StringBuilder sb = new StringBuilder();
		while (it.hasNext()) {
			Symbol s = it.next();
			Address a = s.getAddress();
			Data d = program.getListing().getDefinedDataAt(a);
			String v = (d != null) ? escapeString(String.valueOf(d.getDefaultValueRepresentation()))
					: "(no defined data)";
			sb.append(String.format("%s -> %s : %s%n", label, a, v));
		}
		return sb.toString();
	}
}