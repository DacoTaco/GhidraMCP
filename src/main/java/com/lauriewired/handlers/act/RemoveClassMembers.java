package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;
import com.lauriewired.util.NamespacesUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;

/**
 * Handler for removing members from a C++ class in Ghidra.
 * This modifies the class's associated structure data type.
 * Expects a POST request with parameters:
 * - class_name: Name of the class to modify
 * - parent_namespace: Parent namespace where the class is located (optional)
 * - members: JSON array of member names to remove, or single member name as string
 */
public final class RemoveClassMembers extends Handler {
	/**
	 * Constructor for the RemoveClassMembers handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public RemoveClassMembers(PluginTool tool) {
		super(tool);
	}

	/**
	 * Removes members from a class in the current Ghidra program.
	 *
	 * @param className The name of the class to modify.
	 * @param parentNamespace The parent namespace where the class is located (optional).
	 * @param members string array of member names to remove, or single member name.
	 * @return A message indicating success or failure.
	 */
	@HttpRoute(method=HttpMethod.POST, path="/remove_class_members")
	@McpTool(name = "remove_class_members", description = "Remove members from an existing C++ class.")
    public String removeClassMembers(@Param(name="class_name", description="The name of the class to modify.") String className, @Param(name="parent_namespace", nullable=true, description="The parent namespace where the class is located (optional).") String parentNamespace, 
									 @Param(name="members", description="List of member names to remove from the class. Example: ['old_member', 'unused_field']") String[] members, 
									 @Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("No program loaded");

		return GhidraUtils.RunTransaction(program, "Remove Class Members", () -> {
			DataTypeManager dtm = program.getDataTypeManager();

			GhidraClass classNamespace = NamespacesUtils.FindClass(program, parentNamespace, className);

			// Find the associated structure
			Structure classStruct = DataTypeUtilities.findExistingClassStruct(dtm, classNamespace);
			if (classStruct == null) {
				throw new IllegalArgumentException("No structure found for class '" + className + "'");
			}

			StringBuilder responseBuilder = new StringBuilder("Removing members from class " + className);
			
			int membersRemoved = 0;
			for (String memberName : members) {
				DataTypeComponent component = null;
				for (DataTypeComponent comp : classStruct.getComponents()) {
					if (comp.getFieldName() != null && comp.getFieldName().equals(memberName)) {
						component = comp;
						break;
					}
				}
				
				if (component == null) {
					responseBuilder.append("\nWarning: Member '").append(memberName)
							.append("' not found in class. Skipping.");
					continue;
				}

				int ordinal = component.getOrdinal();
				classStruct.delete(ordinal);
				responseBuilder.append("\nRemoved member '").append(memberName)
						.append("' (ordinal ").append(ordinal).append(")");
				membersRemoved++;
			}

			if (membersRemoved > 0) {
				responseBuilder.append("\nSuccessfully removed ").append(membersRemoved)
						.append(" members from class ").append(className);
			} else {
				responseBuilder.append("\nNo members were removed from class ").append(className);
				throw new IllegalArgumentException(responseBuilder.toString().trim());
			}

			return responseBuilder.toString();
		});
	}
}