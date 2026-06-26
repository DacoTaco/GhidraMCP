package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.EnumUtils.EnumValue;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;

/**
 * Handler for creating a new enum in Ghidra.
 * Expects parameters: name, category (optional), size (optional), values (optional JSON array).
 * Values should be in the format: [{"name": "VALUE1", "value": 0, "comment": "First value"}, ...]
 */
public final class CreateEnum extends Handler {
	/**
	 * Constructs a new CreateEnum handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateEnum(PluginTool tool) {
		super(tool);
	}

	/**
	 * Creates a new enum in Ghidra with the specified parameters.
	 * This method runs on the Swing thread to ensure thread safety when interacting with Ghidra's data types.
	 *
	 * @param name        The name of the enum to create.
	 * @param category    The category path where the enum will be created (optional).
	 * @param size        The size of the enum in bytes (optional, defaults to 4).
	 * @param valuesJson  JSON array of enum values (optional).
	 * @return A message indicating success or failure of the operation.
	 */
	@HttpRoute(method=HttpMethod.POST, path = "/create_enum")
	@McpTool(name = "create_enum", description = "Create a new enum in Ghidra.")
	public String createEnum(@Param(name = "program", nullable = true) String programName, @Param(name = "name") String name,
							 @Param(name = "category", nullable = true) String category, @Param(name = "size", nullable = true) Integer enumSize,
							 @Param(name = "values", nullable = true) EnumValue[] values) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		if(enumSize == null)
			enumSize = 4;

		final AtomicReference<String> result = new AtomicReference<>();
		final int size = enumSize;
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Enum");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);

					if (dtm.getDataType(path, name) != null) {
						result.set("Error: Enum " + name + " already exists in category " + path);
						return;
					}
					
					// Create the enum with specified size
					EnumDataType newEnum = new EnumDataType(path, name, size, dtm);

					StringBuilder responseBuilder = new StringBuilder(
							"Enum " + name + " created successfully in category " + path + " with size " + size + " bytes");

					if (values != null) {
						int valuesAdded = 0;
						for (EnumValue enumValue : values) {
							if (enumValue.name == null || enumValue.name.isEmpty()) {
								responseBuilder.append("\nError: Enum value name cannot be empty. Skipping value.");
								continue;
							}

							// Add the enum value with or without comment
							if (enumValue.comment != null && !enumValue.comment.isEmpty()) {
								newEnum.add(enumValue.name, (long) enumValue.value, enumValue.comment);
							} else {
								newEnum.add(enumValue.name, (long) enumValue.value);
							}
							valuesAdded++;
						}
						responseBuilder.append("\nAdded ").append(valuesAdded).append(" values.");
					}
					
					dtm.addDataType(newEnum, DataTypeConflictHandler.DEFAULT_HANDLER);
					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to create enum: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create enum on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}