package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.StreamSupport;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import com.lauriewired.util.NamespacesUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

/**
 * Handler for renaming a function in the current program.
 * Expects POST parameters: oldName and newName.
 */
public final class RenameFunction extends Handler {
	/**
	 * Constructor for RenameFunction handler.
	 *
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public RenameFunction(PluginTool tool) {
		super(tool);
	}

	/**
	 * Renames a function by its address
	 *
	 * @param functionAddrStr the address of the function as a string
	 * @param newName         the new name for the function
	 * @return true if the rename was successful, false otherwise
	 * @deprecated This method is deprecated and will be removed in future versions. Use {@link #RenameFunction(String, String, String, String)} instead.
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method = HttpMethod.POST, path = "/rename_function_by_address")
    public String RenameFunctionByAddress(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
										  @Param(name = "function_address") String functionAddress, 
            @Param(name = "new_name") String newName) throws Exception {
        RenameFunction(programName, null, functionAddress, newName);
        return "Renamed successfully";
	}

	/**
	 * Renames a function in the given program.
	 *
	 * @param functionName the current name of the function
	 * @param address the address of the function (optional if functionName is provided)
	 * @param newName the new name to set for the function
     * @throws Exception when the function was not found or could not be renamed
	 */
	@HttpRoute(method = HttpMethod.POST, path = "/renameFunction")
    @McpTool(name = "rename_function", description = "Rename a function by its current name OR address to a new user-defined name. A name like 'Class::name' moves the function into that namespace.")
    public void RenameFunction(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "functionName", description = "The name of the function to rename.", nullable = true) String functionName,
            @Param(name = "functionAddress", description = "The address of the function to rename.", nullable = true) String address,
            @Param(name = "newName", description = "The new name for the function.", nullable = false) String newName) throws Exception {
		
        if ((functionName == null || functionName.isEmpty()) && (address == null || address.isEmpty()))
            throw new IllegalArgumentException("Either functionName or functionAddress must be provided.");
		
		Program program = getProgramByName(programName);
		if (program == null)
            throw new Exception("Program not found");

		boolean isAddressProvided = address != null && !address.isEmpty();
		Function func;
        if (!isAddressProvided) {
			func = StreamSupport
				.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)			 
                    .filter(f -> f.getName().equals(functionName) || f.getName(true).equals(functionName))
				.findFirst()
				.orElse(null);
		} 
		else 
		{
			Address addr = AddressUtils.parseAddress(program, address);
			func = program.getListing().getFunctionContaining(addr);
		}

		if (func == null) {
            throw new IllegalArgumentException("Function not found");
		}

		String transactionName = isAddressProvided ? "Rename function by address" : "Rename function by name";
		//copy over so its usable in the transaction lambda
		final Function function = func;
        final AtomicReference<Exception> error = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction(transactionName);
                boolean success = false;
				try {
                    // "A::B::name" moves the function into namespace A::B instead of making a flat name containing "::"
                    String[] parts = NamespacesUtils.SplitQualifiedName(newName);
                    if (parts[0] != null) {
                        NamespacesUtils.MoveFunction(program, function, parts[0], parts[1], false);
                    } else {
					function.setName(newName, SourceType.USER_DEFINED);
                    }
                    success = true;
				} catch (Exception e) {
                    error.set(new Exception("Rename failed: " + e.getMessage(), e));
				} finally {
                    program.endTransaction(tx, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename on Swing thread", e);
throw new Exception("Failed to execute rename on Swing thread: " + e.getMessage(), e);
		}

        if (error.get() != null)
            throw error.get();
    }
}
