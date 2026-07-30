package com.lauriewired.handlers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
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

	private List<Program> getOpenPrograms(String filter)
	{
		Project project = tool.getProject();
		if (project == null) {
			return List.of();
		}

		ToolManager tm = project.getToolManager();
		if (tm == null) {
			return List.of();
		}

		List<Program> programs = new ArrayList<>();
		for (PluginTool runningTool : tm.getRunningTools()) {
			ProgramManager pm = runningTool.getService(ProgramManager.class);
			if (pm == null) {
				continue;
			}

			Program[] opened = pm.getAllOpenPrograms();
			if (filter != null && !filter.isEmpty())
			{
				for (Program p : opened) 
				{
					if (p.getName().equals(filter) || p.getDomainFile().getName().equals(filter) || p.getDomainFile().getPathname().equals(filter)) {
						return List.of(p);
					}
				}
			}

			programs.addAll(Arrays.asList(opened));			
		}

		return List.copyOf(programs);
	}

	protected List<Program> getOpenPrograms(){
		return getOpenPrograms(null);
	}

	protected Program getProgramByName(String programName) {
		return getOpenPrograms(programName).stream().findFirst().orElse(null);
	}
}
