package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Handler to get the current function in Ghidra GUI.
 * Responds with the function name, entry point, and signature.
 */
public final class GetCurrentFunction extends Handler {
	/**
	 * Constructor for the GetCurrentFunction handler.
	 *
	 * @param tool The Ghidra PluginTool instance.
	 */
	public GetCurrentFunction(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves the current function at the current location in the Ghidra GUI.
	 *
	 * @return A string containing the function name, entry point, and signature,
	 *         or an error message if no function is found or if there are issues.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/get_current_function")
    @McpTool(name = "get_current_function", description = "Get the function currently selected by the user")
	public String getCurrentFunction(@Param(name="program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		
		CodeViewerService service = GhidraUtils.resolveService(tool, program, CodeViewerService.class);
		if (service == null)
			return "Code viewer service not available";

		ProgramLocation location = service.getCurrentLocation();
		if (location == null)
			return "No current location";

		Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
		if (func == null)
			return "No function at current location: " + location.getAddress();

		return String.format("Function: %s at %s\nSignature: %s",
				func.getName(),
				func.getEntryPoint(),
				func.getSignature());
	}
}
