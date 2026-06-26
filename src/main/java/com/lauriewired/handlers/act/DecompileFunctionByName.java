package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.http.ParamLocation;
import com.lauriewired.mcp.McpTool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Handler to decompile a function by its name.
 * Expects the function name in the request body.
 */
public final class DecompileFunctionByName extends Handler {
	/**
	 * Constructs a new DecompileFunctionByName handler.
	 * 
	 * @param tool The Ghidra plugin tool instance.
	 */
	public DecompileFunctionByName(PluginTool tool) {
		super(tool);
	}

	/**
	 * Generates the decompiled C pseudocode for the function with the specified
	 * name.
	 * 
	 * @param name The name of the function to decompile.
	 * @return The decompiled C pseudocode or an error message if the function is
	 *         not found.
	 */
	@HttpRoute(method=HttpMethod.POST, path="/decompile")
	@McpTool(name = "decompile_function", description = "Decompile a specific function by name and return the decompiled C code.")
    public String generateResponse(@Param(name="name", location=ParamLocation.Body) String name, @Param(name="program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		DecompInterface decomp = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.setRespectReadOnly(true);
		decomp.setOptions(options);
		decomp.openProgram(program);
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			if (func.getName().equals(name)) {
				DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
				if (result != null && result.decompileCompleted()) {
					return result.getDecompiledFunction().getC();
				} else {
					return "Decompilation failed";
				}
			}
		}
		return "Function not found";
	}
}
