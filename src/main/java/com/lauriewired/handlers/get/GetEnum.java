package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.jetty.http.HttpMethod;

import com.google.gson.Gson;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
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
    public String getEnum(@Param(name = "program", nullable = true) String programName, @Param(name = "name") String enumName, @Param(name = "category", nullable = true) String category) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath path = new CategoryPath(category == null ? "/" : category);
		DataType dt = dtm.getDataType(path, enumName);

		if (dt == null || !(dt instanceof Enum)) {
			return "Error: Enum " + enumName + " not found in category " + path;
		}

		Enum enumDt = (Enum) dt;

		Map<String, Object> enumRepr = new HashMap<>();
		enumRepr.put("name", enumDt.getName());
		enumRepr.put("category", enumDt.getCategoryPath().getPath());
		enumRepr.put("size", enumDt.getLength());
		enumRepr.put("count", enumDt.getCount());
		enumRepr.put("isSigned", enumDt.isSigned());
		enumRepr.put("description", enumDt.getDescription());

		List<Map<String, Object>> valuesList = new ArrayList<>();
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
				Map<String, Object> valueMap = new HashMap<>();
				valueMap.put("name", name);
				valueMap.put("value", value);
				String comment = enumDt.getComment(name);
				valueMap.put("comment", comment != null ? comment : "");
				valuesList.add(valueMap);
			}
		}
		enumRepr.put("values", valuesList);

		Gson gson = new Gson();
		return gson.toJson(enumRepr);
	}
}