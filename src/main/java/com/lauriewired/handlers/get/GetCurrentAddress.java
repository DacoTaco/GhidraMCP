package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Handler to get the current address from the CodeViewerService
 */
public final class GetCurrentAddress extends Handler {

    public GetCurrentAddress(PluginTool tool) {
        super(tool);
    }

	/**
	 * Retrieves the current address from the CodeViewerService
	 *
	 * @return String representation of the current address or an error message
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/get_current_address")
    @McpTool(name = "get_current_address", description = "Get the address currently selected by the user.")
	public String getCurrentAddress(@Param(name = "program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		CodeViewerService service = GhidraUtils.resolveService(tool, program, CodeViewerService.class);
		if (service == null)
			return "Code viewer service not available";

		ProgramLocation location = service.getCurrentLocation();
		return (location != null) ? location.getAddress().toString() : "No current location";
	}
}
