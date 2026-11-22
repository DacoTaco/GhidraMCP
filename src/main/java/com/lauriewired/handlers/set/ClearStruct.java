package com.lauriewired.handlers.set;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

/**
 * Handler for clearing the contents of a structure in Ghidra.
 * This handler processes requests to clear a specified structure by name and
 * category.
 */
public final class ClearStruct extends Handler {
	/**
	 * Constructs a new ClearStruct handler.
	 *
	 * @param tool the PluginTool instance to use for program operations
	 */
	public ClearStruct(PluginTool tool) {
		super(tool);
	}

	/**
	 * Clears the contents of a structure.
	 *
	 * @param structName the name of the structure to clear
	 * @param category   the category of the structure
	 * @return a message indicating the result of the operation
	 */
	@HttpRoute(method = HttpMethod.POST, path = "/clear_struct")
    @McpTool(name = "clear_struct", description = "Remove all members from a structure.")
	public String clearStruct(@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName, 
							  @Param(name = "struct_name", description = "The name of the structure to clear.") String structName, 
							  @Param(name = "category", nullable = true, description = "The category path for the structure. Defaults to root.") String category) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("No program loaded");

		return GhidraUtils.RunTransaction(program, "Clear Struct", () -> {
			DataTypeManager dtm = program.getDataTypeManager();
			CategoryPath path = new CategoryPath(category == null ? "/" : category);
			DataType dt = dtm.getDataType(path, structName);
			if (dt == null || !(dt instanceof Structure)) {
				throw new IllegalArgumentException("Struct " + structName + " not found in category " + path);
			}
			Structure struct = (Structure) dt;
			if (struct.isNotYetDefined()) {
				return "Struct " + structName + " is empty, nothing to clear.";
			}
			struct.deleteAll();
			return "Struct " + structName + " cleared.";
		});
	}
}
