package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

/**
 * Handler for retrieving details of a structure by its name and category.
 * Expects query parameters: name (required), category (optional).
 */
public final class GetStruct extends Handler {
	public record StructMember(String name, String type, int offset, int size, String comment) {}
	public record StructInformation(String name, String category, int size, 
									boolean isNotYetDefined, List<StructMember> members) {}

	/**
	 * Constructor for the GetStruct handler.
	 *
	 * @param tool the PluginTool instance to use for accessing the current program.
	 */
	public GetStruct(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves the structure details as a JSON string.
	 *
	 * @param structName the name of the structure to retrieve.
	 * @param category   the category path where the structure is located
	 *                   (optional).
	 * @return a JSON representation of the structure or an error message if not
	 *         found.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/get_struct")
    @McpTool(name = "get_struct", description = "Get a struct's definition by name and optional category")
	public StructInformation getStruct(@Param(name = "name", description = "The name of the structure.") String structName, @Param(name = "category", nullable=true, description = "The category path for the structure. Defaults to root.") String category, @Param(name = "program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new IllegalArgumentException("No active program found");

		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath path = new CategoryPath(category == null ? "/" : category);
		DataType dt = dtm.getDataType(path, structName);

		if (dt == null || !(dt instanceof Structure))
			throw new IllegalArgumentException("Error: Struct " + structName + " not found in category " + path);

		Structure struct = (Structure) dt;


		List<StructMember> membersList = new ArrayList<>();
		for (DataTypeComponent component : struct.getDefinedComponents()) {
			membersList.add(new StructMember(component.getFieldName(), component.getDataType().getName(), 
											 component.getOffset(), component.getLength(), component.getComment()));
		}

		return new StructInformation(struct.getName(), struct.getCategoryPath().getPath(), 
									 struct.getLength(), struct.isNotYetDefined(), membersList);
	}
}
