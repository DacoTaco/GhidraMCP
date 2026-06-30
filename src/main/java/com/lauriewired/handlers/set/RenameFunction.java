package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
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

	@HttpRoute(method = HttpMethod.POST, path = "/renameFunction")
    @McpTool(name = "rename_function", description = "Rename a function by its current name to a new user-defined name.")
    public String renameFunction(@Param(name = "program", nullable = true) String programName, @Param(name = "oldName", nullable = false) String oldName, @Param(name = "newName", nullable = false) String newName) {
        return rename(programName, oldName, newName)
                ? "Renamed successfully"
                : "Rename failed";
    }

	/**
	 * Renames a function in the current program.
	 *
	 * @param oldName the current name of the function
	 * @param newName the new name to set for the function
	 * @return true if the rename was successful, false otherwise
	 */
	private boolean rename(String programName, String oldName, String newName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return false;

		AtomicBoolean successFlag = new AtomicBoolean(false);
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename function via HTTP");
				try {
					for (Function func : program.getFunctionManager().getFunctions(true)) {
						if (func.getName().equals(oldName)) {
							func.setName(newName, SourceType.USER_DEFINED);
							successFlag.set(true);
							break;
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Error renaming function", e);
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename on Swing thread", e);
		}
		return successFlag.get();
	}
}
