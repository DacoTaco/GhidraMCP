package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

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
	 * @param addressStr the address of the data as a string
	 * @param newName    the new name for the data
	 */

	@HttpRoute(method = HttpMethod.POST, path = "/renameData")
    @McpTool(name = "rename_data", description = "Rename a data label at the specified address.")
	public void renameDataAtAddress(@Param(name = "program", nullable = true) String programName, @Param(name = "address") String addressStr, @Param(name = "newName") String newName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return;

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					Listing listing = program.getListing();
					Data data = listing.getDefinedDataAt(addr);
					if (data != null) {
						SymbolTable symTable = program.getSymbolTable();
						Symbol symbol = symTable.getPrimarySymbol(addr);
						if (symbol != null) {
							symbol.setName(newName, SourceType.USER_DEFINED);
						} else {
							symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Rename data error", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename data on Swing thread", e);
		}
	}
}
