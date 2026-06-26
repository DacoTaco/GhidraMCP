package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.resolveDataType;
import com.lauriewired.util.StructUtils.StructMember;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

/**
 * Handler for creating a new struct in Ghidra.
 * Expects parameters: name, category (optional), size (optional), members (optional JSON array).
 * Members should be in the format: [{"name": "member1", "type": "int", "offset": 0, "comment": "Member 1"}, ...]
 */
public final class CreateStruct extends Handler {
	/**
	 * Constructs a new CreateStruct handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateStruct(PluginTool tool) {
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
	public String createStruct(@Param(name = "name") String name, @Param(name = "category", nullable = true) String category,
							   @Param(name = "size", nullable = true) Integer structSize, @Param(name = "members", nullable = true) StructMember[] members,
							   @Param(name = "program") String programName) {
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

							if (member.offset != -1) {
								newStruct.insertAtOffset((int) member.offset, memberDt, -1, member.name,
										member.comment);
							} else {
								newStruct.add(memberDt, member.name, member.comment);
							}
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
}
