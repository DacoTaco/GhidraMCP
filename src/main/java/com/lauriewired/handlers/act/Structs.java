package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.resolveDataType;
import com.lauriewired.util.StructUtils.StructMember;
import com.lauriewired.util.StructUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

/**
 * Handler for creating structures and adding members to them.
 * Members should be in the format: [{"name": "member1", "type": "int", "offset": 0, "comment": "Member 1"}, ...]
 */
public final class Structs extends Handler {
	/**
	 * Constructs a new Structs handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public Structs(PluginTool tool) {
		super(tool);
	}

	/**
	 * Creates a new struct in Ghidra with the specified parameters.
	 * This method runs on the Swing thread to ensure thread safety when interacting with Ghidra's data types.
	 *
	 * @param name        The name of the struct to create.
	 * @param category    The category path where the struct will be created (optional).
	 * @param size        The size of the struct (optional, defaults to 0).
	 * @param membersJson JSON array of struct members (optional).
	 * @return A message indicating success or failure of the operation.
	 */
	@HttpRoute(method=HttpMethod.POST, path = "/create_struct")
	@McpTool(name = "create_struct", description = "Create a new structure.")
	public String CreateStruct(@Param(name = "name", description = "The name of the new structure.") String name, @Param(name = "category", nullable = true, description = "The category path for the structure (e.g., /my_structs). Defaults to root.") String category,
							   @Param(name = "size", nullable = true, description = "The initial size of the structure.") Integer structSize, @Param(name = "members", nullable = true, description = "List of member dicts with 'name', 'type', and optionally 'offset' and 'comment'. Pointers use asterisk, e.g. void*, int*.") StructMember[] members,
							   @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		if(structSize == null)
			structSize = 0;

		final AtomicReference<String> result = new AtomicReference<>();		
		final int size = structSize;
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Struct");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);

					if (dtm.getDataType(path, name) != null) {
						result.set("Error: Struct " + name + " already exists in category " + path);
						return;
					}
					StructureDataType newStruct = new StructureDataType(path, name, size, dtm);

					StringBuilder responseBuilder = new StringBuilder(
							"Struct " + name + " created successfully in category " + path);

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

							StructUtils.PlaceMember(newStruct, member, memberDt);
							membersAdded++;
						}
						responseBuilder.append("\nAdded ").append(membersAdded).append(" members.");
					}
					dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to create struct: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create struct on Swing thread: " + e.getMessage();
		}
		return result.get();
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
	public String AddStructMembers(@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName, 
								   @Param(name="struct_name", description="The name of the structure to modify.") String structName, 
	                               @Param(name="category", nullable=true, description="The category path for the structure. Defaults to root.") String category, 
								   @Param(name="members", description="List of member dicts with 'name', 'type', and optionally 'offset' and 'comment'. Type should be a builtin C type or Ghidra struct name. If offset is given, it replaces the existing members at that offset.") StructMember[] members) {
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

							StructUtils.PlaceMember(struct, member, memberDt);
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
