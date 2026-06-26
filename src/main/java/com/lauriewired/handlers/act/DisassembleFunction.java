package com.lauriewired.handlers.act;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.http.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * Handler for disassembling a function at a given address in Ghidra
 * 
 * This handler responds to HTTP requests to disassemble a function
 * and returns the assembly code as a string.
 */
public final class DisassembleFunction extends Handler{
	/**
	 * Constructor for the DisassembleFunction handler
	 * 
	 * @param tool the Ghidra plugin tool instance
	 */
	public DisassembleFunction(PluginTool tool) {
		super(tool);
	}

	/**
	 * Disassembles the function at the specified address and returns the assembly
	 * code
	 * 
	 * @param addressStr the address of the function to disassemble
	 * @return a string containing the disassembled function code
	 */
	@HttpRoute(method=HttpMethod.GET, path="/disassemble_function")
	@McpTool(name = "disassemble_function", description = "Get assembly code (address: instruction; comment) for a function.")
    public String disassembleFunction(@Param(name="address") String addressStr, @Param(name="program", nullable=true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			Function func = program.getListing().getFunctionContaining(addr);
			if (func == null)
				return "No function found at or containing address " + addressStr;

			StringBuilder result = new StringBuilder();
			Listing listing = program.getListing();
			Address start = func.getEntryPoint();
			Address end = func.getBody().getMaxAddress();

			InstructionIterator instructions = listing.getInstructions(start, true);
			while (instructions.hasNext()) {
				Instruction instr = instructions.next();
				if (instr.getAddress().compareTo(end) > 0) {
					break; // Stop if we've gone past the end of the function
				}
				String comment = listing.getComment(CommentType.EOL, instr.getAddress());
				comment = (comment != null) ? "; " + comment : "";

				result.append(String.format("%s: %s %s\n",
						instr.getAddress(),
						instr.toString(),
						comment));
			}

			return result.toString();
		} catch (Exception e) {
			return "Error disassembling function: " + e.getMessage();
		}
	}
}
