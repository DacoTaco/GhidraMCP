package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;

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
	public String clearStruct(@Param(name = "program", nullable = true) String programName, @Param(name = "struct_name", description = "The name of the structure to clear.") String structName, @Param(name = "category", nullable = true, description = "The category path for the structure. Defaults to root.") String category){
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Clear Struct");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);
					DataType dt = dtm.getDataType(path, structName);
					if (dt == null || !(dt instanceof Structure)) {
						result.set("Error: Struct " + structName + " not found in category " + path);
						return;
					}
					Structure struct = (Structure) dt;
					if (struct.isNotYetDefined()) {
						result.set("Struct " + structName + " is empty, nothing to clear.");
						success = true; // Not an error state
						return;
					}
					struct.deleteAll();
					result.set("Struct " + structName + " cleared.");
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to clear struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute clear struct on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
