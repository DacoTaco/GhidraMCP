package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Handler to decompile a function by its address in the current program.
 * This handler responds to HTTP requests with the decompiled C code of the function
 * at the specified address.
 */
public final class DecompileFunctionByAddress extends Handler {
	/**
	 * Constructor for the DecompileFunctionByAddress handler
	 *
	 * @param tool the PluginTool instance to interact with Ghidra
	 */
	public DecompileFunctionByAddress(PluginTool tool) {
		super(tool);
	}
	
	/**
	 * Decompiles the function at the specified address in the current program.
	 *
	 * @param addressStr the address of the function to decompile
	 * @return the decompiled C code or an error message
	 */
	@HttpRoute(method=HttpMethod.GET, path="/decompile_function")
	@McpTool(name = "decompile_function_by_address", description = "Decompile a function at the given address.")
	public String decompileFunctionByAddress(@Param(name="address") String addressStr, @Param(name="program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getListing().getFunctionContaining(addr);
			if (func == null)
				return "No function found at or containing address " + addressStr;

			DecompInterface decomp = new DecompInterface();
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(program);
			decomp.setOptions(opts);
			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

			return (result != null && result.decompileCompleted())
					? result.getDecompiledFunction().getC()
					: "Decompilation failed";
		} catch (Exception e) {
			return "Error decompiling function: " + e.getMessage();
		}
	}
}
