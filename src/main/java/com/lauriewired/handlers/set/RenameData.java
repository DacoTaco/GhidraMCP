package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Handler for renaming data at a specific address in the current program.
 * Expects POST parameters: "address" (the address of the data) and "newName"
 * (the new name).
 */
public final class RenameData extends Handler {
	/**
	 * Constructs a new RenameData handler.
	 *
	 * @param tool the PluginTool instance to use for program access
	 */
	public RenameData(PluginTool tool) {
		super(tool);
	}

	/**
	 * Renames the data at the specified address in the current program.
	 * If the data exists, it updates its name; otherwise, it creates a new label.
	 *
     * @param addressStr the address as a string
     * @param newName the new name, may be qualified like "A::name"
     * @param namespace optional namespace to put the label in
     * @throws Exception when the label could not be renamed
	 */
	@HttpRoute(method = HttpMethod.POST, path = "/renameData")
    @McpTool(name = "rename_data", description = "Rename a data label at the specified address.")
    public void renameDataAtAddress(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address") String addressStr, @Param(name = "newName") String newName,
            @Param(name = "namespace", nullable = true) String namespacePath) throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
            throw new Exception("Program not found");

        Address addr = AddressUtils.parseAddress(program, addressStr);
        String[] parts = NamespacesUtils.SplitQualifiedName(newName);
        if (parts[0] != null && !NamespacesUtils.IsGlobalNamespace(namespacePath))
            throw new IllegalArgumentException("Give the namespace either in newName or in namespace, not both");
		
        final String labelName = parts[1];
        final String labelNamespace = parts[0] != null ? parts[0] : namespacePath;

        final AtomicReference<Exception> error = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data");
                boolean success = false;
                try {
                    SymbolTable symbolTable = program.getSymbolTable();
                    Namespace namespace = NamespacesUtils.GetOrCreateNamespace(program, labelNamespace, false);
                    Symbol symbol = symbolTable.getPrimarySymbol(addr);

                    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION)
					{
                        error.set(new IllegalArgumentException(addr + " is the entry of function " + symbol.getName(true) + ", use rename_function"));
                        return;
                    }

                    if (symbol == null)
                        symbolTable.createLabel(addr, labelName, namespace, SourceType.USER_DEFINED);
                    else
                        symbol.setNameAndNamespace(labelName, namespace, SourceType.USER_DEFINED);
                    success = true;
				} catch (Exception e) {
                    error.set(new Exception("Failed to rename data: " + e.getMessage(), e));
				} finally {
                    program.endTransaction(tx, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
            throw new Exception("Failed to execute rename data on Swing thread: " + e.getMessage(), e);
        }

        if (error.get() != null)
            throw error.get();
	}
}
