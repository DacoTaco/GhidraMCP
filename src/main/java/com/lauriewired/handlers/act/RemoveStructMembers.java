package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.google.gson.Gson;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.convertObject;
import static com.lauriewired.util.ParseUtils.mcpError;
import static com.lauriewired.util.ParseUtils.mcpSuccess;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Handler for removing members from a structure in Ghidra.
 * Expects a POST request with parameters:
 * - struct_name: Name of the structure to modify
 * - category: Category path where the structure is located (optional)
 * - members: JSON array of member names to remove, or single member name as string
 */
public final class RemoveStructMembers extends Handler {
	/**
	 * Constructor for the RemoveStructMembers handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public RemoveStructMembers(PluginTool tool) {
		super(tool);
	}
	
	/**
	 * Removes members from a structure in the current Ghidra program.
	 *
	 * @param structName The name of the structure to modify.
	 * @param category The category path where the structure is located (optional).
	 * @param membersParam JSON array of member names to remove, or single member name.
	 * @return A message indicating success or failure.
	 */
	@HttpRoute(method=HttpMethod.POST, path="/remove_struct_members")
	@McpTool(name="remove_struct_members", description="Remove members from an existing struct.")
	public String removeStructMembers(@Param(name="struct_name") String structName, @Param(name="category", nullable=true) String category, 
									   @Param(name="members") String[] members, @Param(name="category", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Remove Struct Members");
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

					StringBuilder responseBuilder = new StringBuilder("Removing members from struct " + structName);

					int membersRemoved = 0;
					for (String memberName : members) {
						DataTypeComponent component = null;
						for (DataTypeComponent comp : struct.getComponents()) {
							if (comp.getFieldName() != null && comp.getFieldName().equals(memberName)) {
								component = comp;
								break;
							}
						}
						
						if (component == null) {
							responseBuilder.append("\nWarning: Member '").append(memberName)
									.append("' not found in struct. Skipping.");
							continue;
						}

						int ordinal = component.getOrdinal();
						struct.delete(ordinal);
						responseBuilder.append("\nRemoved member '").append(memberName)
								.append("' (ordinal ").append(ordinal).append(")");
						membersRemoved++;
					}

					if (membersRemoved > 0) {
						responseBuilder.append("\nSuccessfully removed ").append(membersRemoved)
								.append(" members from struct ").append(structName);
						success = true;
					} else {
						responseBuilder.append("\nNo members were removed from struct ").append(structName);
					}

					result.set(responseBuilder.toString());

				} catch (Exception e) {
					result.set("Error: Failed to remove members from struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute remove struct members on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}