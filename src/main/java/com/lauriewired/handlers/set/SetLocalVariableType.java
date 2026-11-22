package com.lauriewired.handlers.set;

import java.util.Iterator;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import com.lauriewired.util.GhidraUtils;
import static com.lauriewired.util.GhidraUtils.resolveDataType;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Handler for setting the type of a local variable in a function. This handler
 * allows users to specify a function address, variable name, and the new type
 * they want to set for that variable.
 */
public final class SetLocalVariableType extends Handler {

    /**
     * Constructor for the SetLocalVariableType handler.
     *
     * @param tool The PluginTool instance to use for accessing the current
     * program.
     */
    public SetLocalVariableType(PluginTool tool) {
        super(tool);
    }

    @HttpRoute(method = HttpMethod.POST, path = "/set_local_variable_type")
    @McpTool(name = "set_local_variable_type", description = "Set a local variable's type.")
    public String handleRequest(@Param(name = "function_address") String functionAddress, @Param(name = "variable_name") String variableName,
            @Param(name = "new_type") String newType,
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) throws Exception {
        // Capture detailed information about setting the type
        StringBuilder responseMsg = new StringBuilder();
        responseMsg.append("Setting variable type: ").append(variableName)
                .append(" to ").append(newType)
                .append(" in function at ").append(functionAddress).append("\n\n");

        // Attempt to find the data type in various categories
        Program program = getProgramByName(programName);
        if (program != null) {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
            if (directType != null) {
                responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
            } else if (newType.startsWith("P") && newType.length() > 1) {
                String baseTypeName = newType.substring(1);
                DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                if (baseType != null) {
                    responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                } else {
                    responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                }
            } else {
                responseMsg.append("Type not found directly: ").append(newType).append("\n");
            }
        }

        // Try to set the type
        setLocalVariableType(programName, functionAddress, variableName, newType);
        responseMsg.append("\nResult: Variable type set successfully");

        return responseMsg.toString();
    }

    /**
     * Sets the type of a local variable in a function.
     *
     * @param functionAddrStr The address of the function as a string.
     * @param variableName The name of the variable to change.
     * @param newType The new type to set for the variable.
     * @throws Exception when the type could not be set
     */
    private void setLocalVariableType(String programName, String functionAddrStr, String variableName, String newType) throws Exception {
        // Input validation
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("No program loaded");
        }
        if (functionAddrStr == null || functionAddrStr.isEmpty()
                || variableName == null || variableName.isEmpty()
                || newType == null || newType.isEmpty()) {
            throw new IllegalArgumentException("function_address, variable_name and new_type are required");
        }

        applyVariableType(program, functionAddrStr, variableName, newType);
    }

    /**
     * Applies the new type to the specified variable in the given function.
     * The decompile runs on this thread, only the database change runs on the
     * Swing thread inside the transaction.
     *
     * @param program The current program.
     * @param functionAddrStr The address of the function as a string.
     * @param variableName The name of the variable to change.
     * @param newType The new type to set for the variable.
     * @throws Exception when the type could not be applied
     */
    private void applyVariableType(Program program, String functionAddrStr,
            String variableName, String newType) throws Exception {
        // Find the function
        Address addr = AddressUtils.parseAddress(program, functionAddrStr);
        Function func = program.getListing().getFunctionContaining(addr);

        if (func == null) {
            throw new IllegalArgumentException("Could not find function at address: " + functionAddrStr);
        }

        DecompileResults results = decompileFunction(func, program);
        if (results == null || !results.decompileCompleted()) {
            throw new Exception("Could not decompile function at address: " + functionAddrStr);
        }

        ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            throw new Exception("No high function available");
        }

        // Find the symbol by name
        HighSymbol symbol = findSymbolByName(highFunction, variableName);
        if (symbol == null) {
            throw new IllegalArgumentException("Could not find variable '" + variableName + "' in decompiled function");
        }

        // look for HighVariable associated with the symbol
        // if the symbol is a decompiler placeholder, it may not have a HighVariable, which is caught further down
        HighVariable highVar = symbol.getHighVariable();
        if (highVar != null) {
            Msg.info(this, "Found high variable for: '" + variableName + "' with current type " + highVar.getDataType().getName());
        } else {
            Msg.warn(this, "High symbol found for '" + variableName + "' but no HighVariable is attached");
        }

        // Find the data type
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = resolveDataType(tool, program, dtm, newType);

        if (dataType == null) {
            throw new IllegalArgumentException("Could not resolve data type: " + newType);
        }

        Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

        // Apply the type change in a transaction
        updateVariableType(program, symbol, dataType);
    }

    /**
     * Helper method to find a data type by name in all categories, handling
     * case sensitivity.
     *
     * @param dtm The data type manager to search in.
     * @param typeName The name of the type to find.
     * @return The DataType if found, or null if not found.
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Searches for a data type by name in all categories of the
     * DataTypeManager. This method checks both exact and case-insensitive
     * matches.
     *
     * @param dtm The DataTypeManager to search in.
     * @param name The name of the data type to search for.
     * @return The DataType if found, or null if not found.
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive)
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    /**
     * Find a symbol by name in the local symbol map of the high function.
     *
     * @param highFunction The high function to search in.
     * @param variableName The name of the variable to find.
     * @return The HighSymbol if found, or null if not found.
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile the function to access its high-level representation.
     *
     * @param func The function to decompile.
     * @param program The current program.
     * @return The DecompileResults containing the decompiled function.
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(program);
        decomp.setOptions(opts);
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Update the variable type in the database using HighFunctionDBUtil.
     *
     * @param program The current program.
     * @param symbol The high symbol representing the variable.
     * @param dataType The new data type to set for the variable.
     * @throws Exception when the type could not be set
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType) throws Exception {
        GhidraUtils.RunTransaction(program, "Set variable type", () -> {
            // Use HighFunctionDBUtil to update the variable with the new type. it can handle both user defined high variables and decompiler placeholder symbols.
            HighFunctionDBUtil.updateDBVariable(
                    symbol, // The high symbol to modify
                    symbol.getName(), // Keep original name
                    dataType, // The new data type
                    SourceType.USER_DEFINED // Mark as user-defined
            );
            return null;
        });
        Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
    }
}
