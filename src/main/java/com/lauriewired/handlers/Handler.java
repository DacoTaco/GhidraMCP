package com.lauriewired.handlers;

import com.lauriewired.util.GhidraUtils;
import com.sun.net.httpserver.HttpExchange;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Abstract class representing a handler for HTTP requests in a Ghidra
 * PluginTool.
 * Subclasses must implement the handle method to define how requests are
 * processed.
 */
public abstract class Handler {
	/** The PluginTool instance this handler is associated with. */
	protected final PluginTool tool;

	/**
	 * Constructs a new Handler with the specified PluginTool and path.
	 *
	 * @param tool the PluginTool instance this handler is associated with
	 */
	protected Handler(PluginTool tool) {
		this.tool = tool;
	}

	public Program getProgramByName(String programName) {
		return GhidraUtils.getProgramByName(tool, programName);
    }
}
