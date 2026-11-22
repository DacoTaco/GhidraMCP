package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.resolveDataType;
import com.lauriewired.util.StructUtils.StructMember;
import com.lauriewired.util.StructUtils;
import com.lauriewired.util.GhidraUtils;
import com.lauriewired.util.NamespacesUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Handler for creating C++ classes and adding members to them.
 */
public final class Classes extends Handler {

	public Classes(PluginTool tool) {
		super(tool);
	}

	/**
	 * Creates a C++ class in Ghidra with the specified parameters.
	 *
	 * @param programName The name of the program containing the class.
	 * @param name The name of the class to create.
	 * @param parentNamespace The parent namespace (null for global).
	 * @param membersJson JSON string representing class members.
	 * @return A status message indicating success or failure.
	 */
	@HttpRoute(method=HttpMethod.POST, path = "/create_class")
	@McpTool(name = "create_class", description = "Create a new C++ class in Ghidra.")
	public String CreateClass(@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName, 
							  @Param(name = "name") String name,
							  @Param(name = "parent_namespace", nullable = true) String parentNamespace, 
							  @Param(name = "members", nullable = true) StructMember[] members) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("No program loaded");

		return GhidraUtils.RunTransaction(program, "Create Class", () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			DataTypeManager dtm = program.getDataTypeManager();

			// Resolve parent namespace
			Namespace parent = null;
			if (parentNamespace != null && !parentNamespace.isEmpty()) {
				parent = symbolTable.getNamespace(parentNamespace, program.getGlobalNamespace());
				if (parent == null) {
					throw new IllegalArgumentException("Parent namespace '" + parentNamespace + "' not found");
				}
			}

			// Create the class namespace
			GhidraClass classNamespace;
			try {
				classNamespace = symbolTable.createClass(parent, name, SourceType.USER_DEFINED);
			} catch (DuplicateNameException e) {
				throw new IllegalArgumentException("Class '" + name + "' already exists in namespace " + 
						(parent != null ? parent.getName() : "global"));
			} catch (InvalidInputException e) {
				throw new IllegalArgumentException("Invalid class name '" + name + "': " + e.getMessage());
			}

			StringBuilder responseBuilder = new StringBuilder(
					"Class " + name + " created successfully");
			if (parent != null) {
				responseBuilder.append(" in namespace ").append(parent.getName());
			}

			// Create associated structure data type for the class
			CategoryPath classCategory = DataTypeUtilities.getDataTypeCategoryPath(new CategoryPath("/classes"), classNamespace);
			StructureDataType classStruct = new StructureDataType(classCategory, name, 0, dtm);

			// Add members if provided
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

					StructUtils.PlaceMember(classStruct, member, memberDt);
					membersAdded++;
				}
				responseBuilder.append("\nAdded ").append(membersAdded).append(" members to class structure.");
			}

			// Add the structure to the data type manager
			dtm.addDataType(classStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
			
			responseBuilder.append("\nClass structure created in category: ").append(classCategory);
			return responseBuilder.toString();
		});
	}

	/**
	 * Adds members to a class in the current Ghidra program.
	 *
	 * @param className The name of the class to modify.
	 * @param parentNamespace The parent namespace where the class is located (optional).
	 * @param membersJson JSON array of members to add.
	 * @return A message indicating success or failure.
	 */
	@McpTool(name = "add_class_members", description = "Add members to an existing C++ class.")
	@HttpRoute(method = HttpMethod.POST, path = "/add_class_members")
	public String AddClassMembers(@Param(name = "class_name", description = "The name of the class to modify.") String className, 
								  @Param(name = "parent_namespace", nullable = true, description = "The parent namespace where the class is located (optional).") String parentNamespace,
								  @Param(name = "members", description = "List of member dicts with 'name', 'type', and optionally 'offset' and 'comment'. Example: [{'name': 'health', 'type': 'float'}]") StructMember[] members, 
								  @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("No program loaded");

		return GhidraUtils.RunTransaction(program, "Add Class Members", () -> {
			DataTypeManager dtm = program.getDataTypeManager();

			GhidraClass classNamespace = NamespacesUtils.FindClass(program, parentNamespace, className);

			// Find the associated structure
			Structure classStruct = DataTypeUtilities.findExistingClassStruct(dtm, classNamespace);
			if (classStruct == null) {
				throw new IllegalArgumentException("No structure found for class '" + className + "'");
			}

			StringBuilder responseBuilder = new StringBuilder("Adding members to class " + className);

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

					// Check if member already exists
					DataTypeComponent existingComponent = null;
					for (DataTypeComponent comp : classStruct.getComponents()) {
						if (comp.getFieldName() != null && comp.getFieldName().equals(member.name)) {
							existingComponent = comp;
							break;
						}
					}
					if (existingComponent != null) {
						responseBuilder.append("\nWarning: Member '").append(member.name)
								.append("' already exists. Skipping.");
						continue;
					}

					StructUtils.PlaceMember(classStruct, member, memberDt);
					if (member.offset != -1) {
						responseBuilder.append("\nAdded member '").append(member.name)
								.append("' at offset ").append((int) member.offset);
					} else {
						responseBuilder.append("\nAdded member '").append(member.name)
								.append("' after last defined member");
					}
					membersAdded++;
				}
				responseBuilder.append("\nSuccessfully added ").append(membersAdded).append(" members to class ").append(className);
				if (membersAdded == 0)
					throw new IllegalArgumentException(responseBuilder.toString().trim());
				return responseBuilder.toString();
			}
			return null;
		});
	}
}