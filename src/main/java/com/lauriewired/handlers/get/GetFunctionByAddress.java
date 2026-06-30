package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Handler to get function details by address
 */
public final class GetFunctionByAddress extends Handler {
	public GetFunctionByAddress(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves function details by address
	 *
	 * @param addressStr the address as a string
	 * @return a string containing function details or an error message
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/get_function_by_address")
    @McpTool(name = "get_function_by_address", description = "Get a function by its address")
	public String getFunctionByAddress(@Param(name = "address") String addressStr, @Param(name = "program", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getFunctionManager().getFunctionAt(addr);

			if (func == null)
				return "No function found at address " + addressStr;

			return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
					func.getName(),
					func.getEntryPoint(),
					func.getSignature(),
					func.getEntryPoint(),
					func.getBody().getMinAddress(),
					func.getBody().getMaxAddress());
		} catch (Exception e) {
			return "Error getting function: " + e.getMessage();
		}
	}
}
