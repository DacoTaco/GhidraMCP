package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Program;

/**
 * Handler for retrieving details of a typedef by its name and category. Expects
 * query parameters: name (required), category (optional).
 */
public final class GetTypedef extends Handler {

    /**
     * @param name the name of the typedef.
     * @param category the category path the typedef is located in.
     * @param size the size of the typedef in bytes.
     * @param type the data type the typedef directly refers to.
     * @param baseType the data type at the end of the typedef chain.
     * @param isPointer whether the typedef resolves to a pointer.
     */
    public record TypedefInformation(String name, String category, int size,
            String type, String baseType, boolean isPointer) {

    }

    /**
     * Constructor for the GetTypedef handler.
     *
     * @param tool the PluginTool instance to use for accessing the current
     * program.
     */
    public GetTypedef(PluginTool tool) {
        super(tool);
    }

    /**
     * Retrieves the typedef details as a JSON string.
     *
     * @param typedefName the name of the typedef to retrieve.
     * @param category the category path to search, including its subcategories
     * (optional, defaults to the root which searches everything).
     * @return a JSON representation of the typedef or an error message if not
     * found.
     */
    @HttpRoute(method = HttpMethod.GET, path = "/get_typedef")
    @McpTool(name = "get_typedef", description = "Get a typedef's definition by name and optional category")
    public TypedefInformation getTypedef(@Param(name = "name", description = "The name of the typedef.") String typedefName,
            @Param(name = "category", nullable = true, description = "The category path to search in, including all its subcategories. Defaults to root ('/'), which searches everything. A typedef directly in this category takes precedence; otherwise the name must be unique below it.") String category,
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new IllegalArgumentException("No active program found");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath path = new CategoryPath(category == null ? "/" : category);
        TypeDef typedef = GhidraUtils.findDataType(TypeDef.class, dtm, typedefName, path);

        return new TypedefInformation(typedef.getName(), typedef.getCategoryPath().getPath(),
                typedef.getLength(), typedef.getDataType().getDisplayName(),
                typedef.getBaseDataType().getDisplayName(), typedef.isPointer());
    }
}
