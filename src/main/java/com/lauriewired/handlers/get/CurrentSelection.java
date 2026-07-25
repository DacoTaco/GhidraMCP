package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
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
public final class CurrentSelection extends Handler {
	/**
	 * Constructor for the CurrentSelection handler.
	 *
	 * @param tool The Ghidra PluginTool instance.
	 */
	public CurrentSelection(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves the current address from the CodeViewerService
	 *
	 * @return String representation of the current address or an error message
	 * @deprecated This method works, but was merged into {@link #GetCurrentSelection(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method = HttpMethod.GET, path = "/get_current_address")
    public String getCurrentAddress(@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) {
		return GetCurrentSelection(true, programName);
	}

	/**
	 * Retrieves the current function at the current location in the Ghidra GUI.
	 *
	 * @return A string containing the function name, entry point, and signature,
	 *         or an error message if no function is found or if there are issues.
	 * @deprecated This method works, but was merged into {@link #GetCurrentSelection(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method = HttpMethod.GET, path = "/get_current_function")
    public String getCurrentFunction(@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) {
		return GetCurrentSelection(false, programName);
	}

	/**
	 * Retrieves the current function at the current location in the Ghidra GUI.
	 *
	 * @return A string containing the function name, entry point, and signature,
	 *         or an error message if no function is found or if there are issues.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/current_selection")
    @McpTool(name = "current_selection", description = "Get the currently, by the user, selected address or function")
	public String GetCurrentSelection(@Param(name="get_function", description="if true, will return the current function", nullable=true) Boolean getFunction,
									  @Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		
		CodeViewerService service = GhidraUtils.resolveService(tool, program, CodeViewerService.class);
		if (service == null)
			return "Code viewer service not available";

		ProgramLocation location = service.getCurrentLocation();
		if (location == null)
			return "No current location";

		if(getFunction == null || !getFunction)
			return location.getAddress().toString();
		
		Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
		if (func == null)
			return "No function at current location: " + location.getAddress();

		return String.format("Function: '%s' at %s",
				func.getSignature(),
				func.getEntryPoint());
	}
}
