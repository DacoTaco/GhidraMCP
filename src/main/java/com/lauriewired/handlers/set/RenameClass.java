package com.lauriewired.handlers.set;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;
import com.lauriewired.util.NamespacesUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

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
							  @Param(name = "namespace", nullable = true, description = "The parent namespace where the class is located (optional).") String namespace) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception("No program loaded");

		return GhidraUtils.RunTransaction(program, "Rename Class", () -> {
			DataTypeManager dtm = program.getDataTypeManager();

			GhidraClass classNamespace = NamespacesUtils.FindClass(program, namespace, className);

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

			return responseBuilder.toString();
		});
	}
}
