package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.resolveDataType;
import com.lauriewired.util.StructUtils.StructMember;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

/**
 * Handler for adding members to a structure in Ghidra.
 * Expects a POST request with parameters:
 * - struct_name: Name of the structure to modify
 * - category: Category path where the structure is located (optional)
 * - members: JSON array of members to add, each with fields:
 *   - type: Data type of the member
 *   - name: Name of the member
 *   - comment: Comment for the member (optional)
 *   - offset: Offset in bytes (optional, -1 for next available position)
 */
public final class AddStructMembers extends Handler {
	
	public AddStructMembers(PluginTool tool) {
        super(tool);
    }

	/**
	 * Adds members to a structure in the current Ghidra program.
	 *
	 * @param programName The name of the program containing the structure.
	 * @param structName The name of the structure to modify.
	 * @param category   The category path where the structure is located (optional).
	 * @param membersJson JSON array of members to add.
	 * @return A message indicating success or failure.
	 */
	@HttpRoute(method=HttpMethod.POST, path="/add_struct_members")
	@McpTool(name = "add_struct_members", description = "Add members to an existing structure.")
	public String addStructMembers(@Param(name="program", nullable=true) String programName, @Param(name="struct_name") String structName, 
	                               @Param(name="category", nullable=true) String category, @Param(name="members") StructMember[] members) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Add Struct Member");
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

					StringBuilder responseBuilder = new StringBuilder();

					if (members != null) {
						int membersAdded = 0;
						for (StructMember member : members) {
							DataType memberDt = resolveDataType(tool, program, dtm, member.type);
							if (memberDt == null) {
								responseBuilder.append("\nError: Could not resolve data type '").append(member.type)
										.append("' for member '").append(member.name)
										.append("'. Aborting further member creation.");
								break;
							}

							if (member.offset != -1) {
								struct.insertAtOffset((int) member.offset, memberDt, -1, member.name, member.comment);
							} else {
								struct.add(memberDt, member.name, member.comment);
							}
							membersAdded++;
						}
						responseBuilder.append("\nAdded ").append(membersAdded).append(" members.");
						result.set(responseBuilder.toString());
						success = membersAdded > 0;
					}

				} catch (Exception e) {
					result.set("Error: Failed to add member to struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute add struct member on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
