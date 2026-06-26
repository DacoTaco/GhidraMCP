package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.GhidraUtils.resolveDataType;
import com.lauriewired.util.StructUtils.StructMember;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Handler for creating a new C++ class in Ghidra.
 * This creates both a class namespace and an associated structure data type.
 * Expects parameters: name, parent_namespace (optional), members (optional JSON array).
 * Members should be in the format: [{"name": "member1", "type": "int", "offset": 0, "comment": "Member 1"}, ...]
 */
public final class CreateClass extends Handler {
	/**
	 * Constructs a new CreateClass handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public CreateClass(PluginTool tool) {
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
	public String createClassInGhidra(@Param(name = "program", nullable = true) String programName, @Param(name = "name") String name,
									  @Param(name = "parent_namespace", nullable = true) String parentNamespace, @Param(name = "members", nullable = true) StructMember[] members){
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
					CategoryPath classCategory = getCategoryPath(classNamespace);
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

							if (member.offset != -1) {
								classStruct.insertAtOffset((int) member.offset, memberDt, -1, member.name,
										member.comment);
							} else {
								classStruct.add(memberDt, member.name, member.comment);
							}
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
	 * Get the category path for a class namespace.
	 * This creates a category path based on the class namespace hierarchy.
	 */
	private CategoryPath getCategoryPath(GhidraClass classNamespace) {
		List<String> pathParts = new ArrayList<>();
		Namespace current = classNamespace;
		
		// Build path from class up to root (excluding global namespace)
		while (current != null && !current.isGlobal()) {
			pathParts.add(0, current.getName()); // Insert at beginning to reverse order
			current = current.getParentNamespace();
		}
		
		// Create category path starting with "/classes"
		if (pathParts.isEmpty()) {
			return new CategoryPath("/classes");
		} else {
			return new CategoryPath("/classes/" + String.join("/", pathParts));
		}
	}
}