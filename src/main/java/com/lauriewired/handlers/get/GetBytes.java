package com.lauriewired.handlers.get;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.hexdump;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Handler to get bytes from a specified address in the current program.
 * Expects query parameters: address=<address> and size=<size>.
 */
public final class GetBytes extends Handler {
	/**
	 * Constructor for the GetBytes handler.
	 * 
	 * @param tool The PluginTool instance to use.
	 */
	public GetBytes(PluginTool tool) {
		super(tool);
	}
	
	/**
	 * Gets the bytes from the specified address in the current program.
	 * 
	 * @param addressStr The address to read from.
	 * @param size       The number of bytes to read.
	 * @return A string representation of the bytes in hex format.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/get_bytes")
	@McpTool(name = "get_bytes", description = "Read raw bytes from memory and return a hex dump.")
	public String getBytes(@Param(name = "address") String addressStr, @Param(name = "size", nullable = true) Integer size, @Param(name = "program", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		int readSize = (size == null) ? 1 : size;
		if (readSize <= 0)
			return "Size must be > 0";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			byte[] buf = new byte[readSize];
			int read = program.getMemory().getBytes(addr, buf);
			return hexdump(addr, buf, read);
		} catch (Exception e) {
			return "Error reading memory: " + e.getMessage();
		}
	}
}