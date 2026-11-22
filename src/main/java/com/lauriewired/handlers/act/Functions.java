package com.lauriewired.handlers.act;

import java.util.Optional;
import java.util.stream.StreamSupport;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import com.lauriewired.util.NamespacesUtils;
import com.lauriewired.util.GhidraUtils;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Handler for creating, deleting, renaming and moving functions between namespaces.
 */
public final class Functions extends Handler {

    /**
     * Constructor for the Functions handler.
     *
     * @param tool the PluginTool instance to interact with Ghidra
     */
    public Functions(PluginTool tool) {
        super(tool);
    }

    /**
     * Creates a function at an address, disassembling it first when needed.
     *
     * @param programName the program to work with
     * @param address the entry point of the new function
     * @param name optional function name, without namespace
     * @param namespacePath optional namespace path, e.g. "A::B"
     * @throws Exception when the function could not be created
     */
    @HttpRoute(method = HttpMethod.POST, path = "/createFunction")
    @McpTool(name = "create_function", description = "Create a function at an address, disassembling it first if needed.")
    public void CreateFunction(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address", description = "Entry point, in hex.") String address,
            @Param(name = "name", nullable = true, description = "Function name, without namespace.") String name,
            @Param(name = "namespace", nullable = true, description = "Namespace path, e.g. 'A::B'. Empty = global.") String namespacePath)
            throws Exception {
        if (name != null && name.contains("::")) {
            throw new IllegalArgumentException("name must not contain '::', put the namespace in 'namespace'");
        }

        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        Address entry = AddressUtils.parseAddress(program, address);
        Function existing = program.getFunctionManager().getFunctionContaining(entry);
        if (existing != null) {
            throw new IllegalArgumentException(entry + " is already part of function " + existing.getName(true));
        }

        GhidraUtils.RunTransaction(program, "Create function", () -> {
            if (program.getListing().getInstructionAt(entry) == null) {
                DisassembleCommand disassemble = new DisassembleCommand(entry, null, true);
                if (!disassemble.applyTo(program, TaskMonitor.DUMMY) || program.getListing().getInstructionAt(entry) == null) {
                    throw new Exception("Could not disassemble " + entry + ": " + disassemble.getStatusMsg());
                }
            }

            CreateFunctionCmd create = new CreateFunctionCmd(entry);
            if (!create.applyTo(program, TaskMonitor.DUMMY)) {
                throw new Exception("Could not create function at " + entry + ": " + create.getStatusMsg());
            }

            if (name != null && !name.isBlank()) {
                NamespacesUtils.MoveFunction(program, program.getFunctionManager().getFunctionAt(entry), namespacePath, name, false);
            }
            return null;
        });
    }

    /**
     * Deletes the function with the given entry point. The instructions stay.
     *
     * @param programName the program to work with
     * @param address the entry point of the function
     * @throws Exception when the function could not be deleted
     */
    @HttpRoute(method = HttpMethod.POST, path = "/deleteFunction")
    @McpTool(name = "delete_function", description = "Delete the function at an entry point, the instructions stay.")
    public void DeleteFunction(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address") String address) throws Exception {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        Address entry = AddressUtils.parseAddress(program, address);
        if (program.getFunctionManager().getFunctionAt(entry) == null) {
            throw new IllegalArgumentException("No function starts at " + entry);
        }

        GhidraUtils.RunTransaction(program, "Delete function", () -> {
            if (!program.getFunctionManager().removeFunction(entry)) {
                throw new Exception("Could not delete the function at " + entry);
            }
            return null;
        });
    }

    /**
     * Renames a function by its address
     *
     * @param functionAddress the address of the function as a string
     * @param newName the new name for the function
     * @return a success message, failures throw
     * @deprecated This method is deprecated and will be removed in future
     * versions. Use {@link #RenameFunction(String, String, String, String, String, Boolean)}
     * instead.
     */
    @Deprecated(forRemoval = true)
    @HttpRoute(method = HttpMethod.POST, path = "/rename_function_by_address")
    public String RenameFunctionByAddress(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "function_address") String functionAddress,
            @Param(name = "new_name") String newName) throws Exception {
        RenameFunction(programName, null, functionAddress, newName, null, null);
        return "Renamed successfully";
    }

    /**
     * Renames a function and sets its namespace. An empty namespace moves the
     * function to the global namespace.
     *
     * @param functionName the current name of the function
     * @param address the address of the function (optional if functionName is
     * provided)
     * @param newName the new name
     * @param namespacePath the namespace path, e.g. "A::B". Empty or "global"
     * for the global namespace.
     * @param asClass create the namespace as a class or convert it to one
     * @throws Exception when the function was not found or could not be renamed
     */
    @HttpRoute(method = HttpMethod.POST, path = "/renameFunction")
    @McpTool(name = "rename_function", description = "Rename a function by its current name OR address to a new user-defined name, and set its namespace. The name must not contain '::', the namespace goes in 'namespace'.")
    public void RenameFunction(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "functionName", description = "The name of the function to rename.", nullable = true) String functionName,
            @Param(name = "functionAddress", description = "The address of the function to rename.", nullable = true) String address,
            @Param(name = "newName", description = "The new name for the function.", nullable = false) String newName,
            @Param(name = "namespace", nullable = true, description = "Namespace path, e.g. 'A::B'. When no namespace is given, the function is moved to the global namespace.") String namespacePath,
            @Param(name = "asClass", nullable = true, description = "Make the namespace a class. Does not change the calling convention.") Boolean asClass) throws Exception {

        if ((functionName == null || functionName.isEmpty()) && (address == null || address.isEmpty())) {
            throw new IllegalArgumentException("Either functionName or functionAddress must be provided.");
        }
        if (newName == null || newName.isBlank()) {
            throw new IllegalArgumentException("newName is required");
        }
        if (newName.contains("::")) {
            throw new IllegalArgumentException("newName must not contain '::', put the namespace in 'namespace'");
        }

        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        Function func;
        if (address == null || address.isEmpty()) {
            func = StreamSupport
                    .stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
                    .filter(f -> f.getName().equals(functionName) || f.getName(true).equals(functionName))
                    .findFirst()
                    .orElse(null);
        } else {
            Address addr = AddressUtils.parseAddress(program, address);
            func = program.getListing().getFunctionContaining(addr);
        }

        if (func == null) {
            throw new IllegalArgumentException("Function not found");
        }

        //copy over so its usable in the transaction lambda
        final Function function = func;
        GhidraUtils.RunTransaction(program, "Rename function", () -> {
            try {
                NamespacesUtils.MoveFunction(program, function, namespacePath, newName, Optional.ofNullable(asClass).orElse(false));
            } catch (Exception e) {
                throw new Exception("Rename failed: " + e.getMessage(), e);
            }
            return null;
        });
    }
}
