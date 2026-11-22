package com.lauriewired.handlers.act;

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
    public String removeEnumValues(@Param(name="enum_name", description="The name of the enum to modify.") String enumName, @Param(name="category", nullable=true, description="The category path for the enum (optional, defaults to root).") String category, 
								   @Param(name="values", description="List of value names to remove from the enum. Example: ['OLD_VALUE', 'DEPRECATED_OPTION']") String[] values, 
								   @Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("No program loaded");

		return GhidraUtils.RunTransaction(program, "Remove Enum Values", () -> {
			DataTypeManager dtm = program.getDataTypeManager();
			CategoryPath path = new CategoryPath(category == null ? "/" : category);
			DataType dt = dtm.getDataType(path, enumName);

			if (dt == null || !(dt instanceof EnumDataType)) {
				throw new IllegalArgumentException("Enum " + enumName + " not found in category " + path);
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
			} else {
				responseBuilder.append("\nNo values were removed from enum ").append(enumName);
				throw new IllegalArgumentException(responseBuilder.toString().trim());
			}

			return responseBuilder.toString();
		});
	}
}