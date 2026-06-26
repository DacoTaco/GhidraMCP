package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Handler for renaming a variable in a function.
 * Expects POST parameters: functionName, oldName, newName.
 * Returns a message indicating success or failure.
 */
public final class RenameVariable extends Handler {
	/**
	 * Constructor for the RenameVariable handler.
	 *
	 * @param tool the PluginTool instance
	 */
	public RenameVariable(PluginTool tool) {
		super(tool);
	}
	/**
	 * Renames a variable in the specified function.
	 * 
	 * @param functionName the name of the function containing the variable
	 * @param oldVarName   the current name of the variable to rename
	 * @param newVarName   the new name for the variable
	 * @return a message indicating success or failure
	 */
	@HttpRoute(method=HttpMethod.POST, path="/renameVariable")
	@McpTool(name="rename_variable", description="Rename a local variable within a function.")
	public String renameVariableInFunction(@Param(name="functionName") String functionName, @Param(name="oldName") String oldVarName, 
										   @Param(name="newName") String newVarName, @Param(name="newName", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		DecompInterface decomp = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		opts.grabFromProgram(program);
		decomp.setOptions(opts);
		decomp.openProgram(program);

		Function func = null;
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				func = f;
				break;
			}
		}

		if (func == null) {
			return "Function not found";
		}

		DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
		if (result == null || !result.decompileCompleted()) {
			return "Decompilation failed";
		}

		HighFunction highFunction = result.getHighFunction();
		if (highFunction == null) {
			return "Decompilation failed (no high function)";
		}

		LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
		if (localSymbolMap == null) {
			return "Decompilation failed (no local symbol map)";
		}

		HighSymbol highSymbol = null;
		Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			String symbolName = symbol.getName();

			if (symbolName.equals(oldVarName)) {
				highSymbol = symbol;
			}
			if (symbolName.equals(newVarName)) {
				return "Error: A variable with name '" + newVarName + "' already exists in this function";
			}
		}

		if (highSymbol == null) {
			return "Variable not found";
		}

		boolean commitRequired = checkFullCommit(highSymbol, highFunction);

		final HighSymbol finalHighSymbol = highSymbol;
		final Function finalFunction = func;
		AtomicBoolean successFlag = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename variable");
				try {
					if (commitRequired) {
						HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
								HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
					}
					HighFunctionDBUtil.updateDBVariable(
							finalHighSymbol,
							newVarName,
							null,
							SourceType.USER_DEFINED);
					successFlag.set(true);
				} catch (Exception e) {
					Msg.error(this, "Failed to rename variable", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
			Msg.error(this, errorMsg, e);
			return errorMsg;
		}
		return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
	}

	/**
	 * Checks if a full commit is required for the variable renaming operation.
	 * 
	 * @param highSymbol the HighSymbol representing the variable
	 * @param hfunction  the HighFunction containing the variable
	 * @return true if a full commit is required, false otherwise
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can
			// match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}
}
