package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;

/**
 * Handler for retrieving details of an enum by its name and category.
 * Expects query parameters: name (required), category (optional).
 */
public final class GetEnum extends Handler {

	public record EnumValue(String name, long value, String comment) {}
	public record EnumInformation(String name, String category, int size, int count, 
								  boolean isSigned, String description, List<EnumValue> values) {}

	/**
	 * Constructor for the GetEnum handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public GetEnum(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves the enum details as a JSON string.
	 *
	 * @param enumName the name of the enum to retrieve.
	 * @param category   the category path where the enum is located
	 *                   (optional).
	 * @return a JSON representation of the enum or an error message if not
	 *         found.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/get_enum")
    @McpTool(name = "get_enum", description = "Get an enum's definition from a program")
    public EnumInformation getEnum(@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName, 
								   @Param(name = "name", description = "The name of the enum.") String enumName, 
								   @Param(name = "category", nullable = true, description = "The category path for the enum (defaults to root).") String category) {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new IllegalArgumentException("No active program found with the specified name.");

		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath path = new CategoryPath(category == null ? "/" : category);
		DataType dt = dtm.getDataType(path, enumName);

		if (dt == null || !(dt instanceof Enum))
			throw new IllegalArgumentException("Error: Enum " + enumName + " not found in category " + path);

		Enum enumDt = (Enum) dt;
		List<EnumValue> valuesList = new ArrayList<>();
		String[] names = enumDt.getNames();
		long[] values = enumDt.getValues();
		
		// Create a map for quick lookup of values by name
		Map<String, Long> nameToValue = new HashMap<>();
		for (int i = 0; i < names.length; i++) {
			nameToValue.put(names[i], values[i]);
		}

		// Build the values list
		for (String name : names) {
			Long value = nameToValue.get(name);
			if (value != null) {
				String comment = enumDt.getComment(name);
				EnumValue enumValue = new EnumValue(name, value, comment != null ? comment : "");
				valuesList.add(enumValue);
			}
		}

		return new EnumInformation(enumDt.getName(), enumDt.getCategoryPath().getPath(), enumDt.getLength(), 
								   enumDt.getCount(), enumDt.isSigned(), enumDt.getDescription(), valuesList);
	}
}