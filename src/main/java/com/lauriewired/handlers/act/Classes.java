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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
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
							  @Param(name = "members", nullable = true) StructMember[] members){
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Create Class");
				boolean success = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					DataTypeManager dtm = program.getDataTypeManager();

					// Resolve parent namespace
					Namespace parent = null;
					if (parentNamespace != null && !parentNamespace.isEmpty()) {
						parent = symbolTable.getNamespace(parentNamespace, program.getGlobalNamespace());
						if (parent == null) {
							result.set("Error: Parent namespace '" + parentNamespace + "' not found");
							return;
						}
					}

					// Create the class namespace
					GhidraClass classNamespace;
					try {
						classNamespace = symbolTable.createClass(parent, name, SourceType.USER_DEFINED);
					} catch (DuplicateNameException e) {
						result.set("Error: Class '" + name + "' already exists in namespace " + 
								(parent != null ? parent.getName() : "global"));
						return;
					} catch (InvalidInputException e) {
						result.set("Error: Invalid class name '" + name + "': " + e.getMessage());
						return;
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
					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to create class: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute create class on Swing thread: " + e.getMessage();
		}
		return result.get();
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
								  @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Add Class Members");
				boolean success = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					DataTypeManager dtm = program.getDataTypeManager();

					// Find the class namespace
					Namespace parent = program.getGlobalNamespace();
					if (parentNamespace != null && !parentNamespace.isEmpty()) {
						parent = symbolTable.getNamespace(parentNamespace, program.getGlobalNamespace());
						if (parent == null) {
							result.set("Error: Parent namespace '" + parentNamespace + "' not found");
							return;
						}
					}

					// Find the class by iterating through symbols
					GhidraClass classNamespace = null;
					for (Symbol symbol : symbolTable.getSymbols(className, parent)) {
						if (symbol.getSymbolType() == SymbolType.CLASS) {
							classNamespace = (GhidraClass) symbol.getObject();
							break;
						}
					}

					if (classNamespace == null) {
						result.set("Error: Class '" + className + "' not found" + 
								(parent != null ? " in namespace " + parent.getName() : ""));
						return;
					}

					// Find the associated structure
					Structure classStruct = DataTypeUtilities.findExistingClassStruct(dtm, classNamespace);
					if (classStruct == null) {
						result.set("Error: No structure found for class '" + className + "'");
						return;
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
						result.set(responseBuilder.toString());
						success = membersAdded > 0;
					}

				} catch (Exception e) {
					result.set("Error: Failed to add members to class: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute add class members on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}