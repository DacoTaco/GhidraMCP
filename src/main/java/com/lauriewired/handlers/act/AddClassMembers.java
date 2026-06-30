package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.resolveDataType;
import com.lauriewired.util.StructUtils.StructMember;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Handler for adding members to a C++ class in Ghidra.
 * This modifies both the class namespace and its associated structure data type.
 * Expects a POST request with parameters:
 * - class_name: Name of the class to modify
 * - parent_namespace: Parent namespace where the class is located (optional)
 * - members: JSON array of members to add, each with fields:
 *   - type: Data type of the member
 *   - name: Name of the member
 *   - comment: Comment for the member (optional)
 *   - offset: Offset in bytes (optional, -1 for next available position)
 */
public final class AddClassMembers extends Handler {
	/**
	 * Constructor for the AddClassMembers handler.
	 *
	 * @param tool The Ghidra plugin tool instance.
	 */
	public AddClassMembers(PluginTool tool) {
		super(tool);
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
	public String addClassMembers(@Param(name = "class_name", description = "The name of the class to modify.") String className, @Param(name = "parent_namespace", nullable = true, description = "The parent namespace where the class is located (optional).") String parentNamespace,
								  @Param(name = "members", description = "List of member dicts with 'name', 'type', and optionally 'offset' and 'comment'. Example: [{'name': 'health', 'type': 'float'}]") StructMember[] members, @Param(name = "program", nullable = true) String programName) {
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

							if (member.offset != -1) {
								classStruct.insertAtOffset((int) member.offset, memberDt, -1, member.name, member.comment);
								responseBuilder.append("\nAdded member '").append(member.name)
										.append("' at offset ").append(member.offset);
							} else {
								classStruct.add(memberDt, member.name, member.comment);
								responseBuilder.append("\nAdded member '").append(member.name)
										.append("' at end of structure");
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