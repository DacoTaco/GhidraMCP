package com.lauriewired.handlers.act;

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
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;

/**
 * Handler for removing values from an enum in Ghidra.
 * Expects a POST request with parameters:
 * - enum_name: Name of the enum to modify
 * - category: Category path where the enum is located (optional)
 * - values: JSON array of value names to remove, or single value name as string
 */
public final class RemoveEnumValues extends Handler {
	/**
	 * Constructor for the RemoveEnumValues handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public RemoveEnumValues(PluginTool tool) {
		super(tool);
	}

	/**
	 * Removes values from an enum in the current Ghidra program.
	 *
	 * @param enumName The name of the enum to modify.
	 * @param category The category path where the enum is located (optional).
	 * @param valuesParam JSON array of value names to remove, or single value name.
	 * @return A message indicating success or failure.
	 */
	@HttpRoute(method=HttpMethod.POST, path="/remove_enum_values")
	@McpTool(name = "remove_enum_values", description = "Remove values from an existing enum.")
    public String removeEnumValues(@Param(name="enum_name") String enumName, @Param(name="category", nullable=true) String category, 
								   @Param(name="values") String[] values, @Param(name="program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Remove Enum Values");
				boolean success = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					CategoryPath path = new CategoryPath(category == null ? "/" : category);
					DataType dt = dtm.getDataType(path, enumName);

					if (dt == null || !(dt instanceof EnumDataType)) {
						result.set("Error: Enum " + enumName + " not found in category " + path);
						return;
					}
					EnumDataType enumDt = (EnumDataType) dt;

					StringBuilder responseBuilder = new StringBuilder(
							"Removing values from enum " + enumName);

					int valuesRemoved = 0;
					for (String valueName : values) {
						try {
							// Check if value exists
							boolean valueExists = false;
							String[] enumValueNames = enumDt.getNames();
							for (String existingName : enumValueNames) {
								if (existingName.equals(valueName)) {
									valueExists = true;
									break;
								}
							}

							if (!valueExists) {
								responseBuilder.append("\nWarning: Value '").append(valueName)
										.append("' not found in enum. Skipping.");
								continue;
							}

							// Remove the value
							enumDt.remove(valueName);
							responseBuilder.append("\nRemoved value '").append(valueName).append("'");
							valuesRemoved++;
						} catch (Exception e) {
							responseBuilder.append("\nError removing value '").append(valueName)
									.append("': ").append(e.getMessage());
						}
					}

					if (valuesRemoved > 0) {
						responseBuilder.append("\nSuccessfully removed ").append(valuesRemoved)
								.append(" values from enum ").append(enumName);
						success = true;
					} else {
						responseBuilder.append("\nNo values were removed from enum ").append(enumName);
					}

					result.set(responseBuilder.toString());

				} catch (Exception e) {
					result.set("Error: Failed to remove values from enum: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute remove enum values on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}