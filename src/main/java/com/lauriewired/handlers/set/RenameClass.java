package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Handler for renaming a C++ class in the current program.
 * Renames both the class namespace and its associated structure data type.
 * Expects parameters: class_name, new_name, parent_namespace (optional).
 */
public final class RenameClass extends Handler {
	/**
	 * Constructor for the RenameClass handler.
	 *
	 * @param tool The PluginTool instance to interact with Ghidra.
	 */
	public RenameClass(PluginTool tool) {
		super(tool);
	}

	/**
	 * Renames a class namespace and its associated structure.
	 *
	 * @param programName     The name of the program containing the class.
	 * @param className       The current name of the class.
	 * @param newName         The new name for the class.
	 * @param parentNamespace The parent namespace where the class is located (optional).
	 * @return A status message indicating success or failure.
	 */
	@HttpRoute(method = HttpMethod.POST, path = "/renameClass")
	@McpTool(name = "renameClass", description = "Rename a C++ class. Renames both the class namespace and its associated structure data type.")
	public String renameClass(@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
							  @Param(name = "className", description = "The current name of the class.") String className,
							  @Param(name = "newName", description = "The new name for the class.") String newName,
							  @Param(name = "namespace", nullable = true, description = "The parent namespace where the class is located (optional).") String namespace) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		final AtomicReference<String> result = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int txId = program.startTransaction("Rename Class");
				boolean success = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					DataTypeManager dtm = program.getDataTypeManager();

					// Find the parent namespace
					Namespace parent = program.getGlobalNamespace();
					if (namespace != null && !namespace.isEmpty()) {
						parent = symbolTable.getNamespace(namespace, program.getGlobalNamespace());
						if (parent == null) {
							result.set("Error: Parent namespace '" + namespace + "' not found");
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
						result.set("Error: Class '" + className + "' not found in namespace " + parent.getName());
						return;
					}

					// Look up the structure before renaming, as the lookup is name based
					Structure classStruct = DataTypeUtilities.findExistingClassStruct(dtm, classNamespace);

					classNamespace.getSymbol().setName(newName, SourceType.USER_DEFINED);
					StringBuilder responseBuilder = new StringBuilder("Class " + className + " renamed to " + newName);

					if (classStruct != null) {
						// create_class stores the structure in /classes/<namespaces>/<ClassName>, keep that layout in sync
						CategoryPath structCategory = classStruct.getCategoryPath();
						if (structCategory.getName().equals(className)
								&& structCategory.getPath().startsWith("/classes/")) {
							Category category = dtm.getCategory(structCategory);
							if (category != null)
								category.setName(newName);
						}

						classStruct.setName(newName);
						responseBuilder.append("\nRenamed class structure to ").append(classStruct.getPathName());
					} else {
						responseBuilder.append("\nNo associated class structure found, only the namespace was renamed");
					}

					result.set(responseBuilder.toString());
					success = true;
				} catch (Exception e) {
					result.set("Error: Failed to rename class: " + e.getMessage());
				} finally {
					program.endTransaction(txId, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			return "Error: Failed to execute rename class on Swing thread: " + e.getMessage();
		}
		return result.get();
	}
}
