package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.endpoints.ParamLocation;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
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
 * Handler to decompile a function by its name.
 * Expects the function name in the request body.
 */
public final class DecompileFunction extends Handler {
	/**
	 * Constructs a new DecompileFunction handler.
	 * 
	 * @param tool The Ghidra plugin tool instance.
	 */
	public DecompileFunction(PluginTool tool) {
		super(tool);
	}

	/**
	 * Generates the decompiled C pseudocode for the function with the specified
	 * name.
	 * 
	 * @param name The name of the function to decompile.
	 * @param addressStr the address of the function to decompile
	 * @return The decompiled C pseudocode or an error message if the function is
	 *         not found.
	 * @deprecated This method works, but was merged into {@link #DecompileFunction(String)} instead.
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.POST, path="/decompile")
	public String DecompileFunctionByName(@Param(name="name", location=ParamLocation.Body) String name, 
								   		  @Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) {
		return DecompileFunction(name, null, programName);
	}

	/**
	 * Generates the decompiled C pseudocode for the function with the specified
	 * name.
	 * 
	 * @param name The name of the function to decompile.
	 * @param addressStr the address of the function to decompile
	 * @return The decompiled C pseudocode or an error message if the function is
	 *         not found.
	 */
	@McpTool(name = "decompile_function", description = "Decompile a function based on its name or address and return the decompiled C code.")
	@HttpRoute(method=HttpMethod.GET, path="/decompile_function")
	public String DecompileFunction(@Param(name="name", description="name of the function", nullable=true) String name,
									@Param(name="address", description="address of the function", nullable=true) String addressStr, 
									@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) {
		if((name == null || name.isEmpty()) && (addressStr == null || addressStr.isEmpty()))
			return "Either function name or address must be provided";

		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		Function function = null;
		//decompile by name
		if(name != null && !name.isEmpty()) {
			for (Function func : program.getFunctionManager().getFunctions(true)) {
				if (func.getName().equals(name)) {
					function = func;
					break;
				}
			}
		}
		//decompile by address
		else
		{
			Address addr = program.getAddressFactory().getAddress(addressStr);
			function = program.getListing().getFunctionContaining(addr);
		}

		if (function == null)
			return "No function found with the given parameters";

		DecompInterface decomp = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.setRespectReadOnly(true);
		decomp.setOptions(options);
		decomp.openProgram(program);
		DecompileResults result = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
		if (result != null && result.decompileCompleted()) {
			return result.getDecompiledFunction().getC();
		} else {
			return "Decompilation failed";
		}
	}
}
