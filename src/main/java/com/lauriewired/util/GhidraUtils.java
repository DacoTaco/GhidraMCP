package com.lauriewired.util;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;


/**
 * Utility class for Ghidra-related operations.
 * Provides methods to interact with the current program, resolve data types,
 * and set comments at specific addresses.
 */
public final class GhidraUtils {

	/**
	 * Resolve a program by name using the provided PluginTool. If programName is
	 * null or empty, returns the current program.
	 */
	public static Program getProgramByName(PluginTool tool, String programName) {
		Project project = tool.getProject();
        if (project == null) {
            return null;
        }

		ToolManager tm = project.getToolManager();
		if (tm == null) {
			return null;
		}

		//Lookup program by name across all open programs in all tools
		for (PluginTool runningTool : tm.getRunningTools()) {
			ProgramManager pm = runningTool.getService(ProgramManager.class);
			if (pm == null)
				continue;

			for (Program p : pm.getAllOpenPrograms()) {
				if (programName == null || programName.isEmpty())
					return p;

				if (p.getName().equals(programName)
						|| p.getDomainFile().getName().equals(programName)
						|| p.getDomainFile().getPathname().equals(programName)) {
					return p;
				}
			}
		}
		
        return null;
	}

	public static <T> T resolveService(PluginTool currentTool, Program program, Class<T> serviceClass) 
	{
		if (currentTool == null || serviceClass == null)
			return null;

		// 1. Try current tool first (and optionally verify program context)
		T service = currentTool.getService(serviceClass);
		if (service != null && isProgramInTool(currentTool, program))
			return service;

		Project project = currentTool.getProject();
		if (project == null)
			return null;

		ToolManager tm = project.getToolManager();
		if (tm == null)
			return null;

		// 2. Search other tools, but ONLY those that have the program open
		for (PluginTool tool : tm.getRunningTools()) {
			if (tool == null)
				continue;

			if (!isProgramInTool(tool, program))
				continue;

			service = tool.getService(serviceClass);
			if (service != null)
				return service;
		}

		return null;
	}

	private static boolean isProgramInTool(PluginTool tool, Program program) {
		if (tool == null || program == null)
			return false;

		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null)
			return false;

		for (Program p : pm.getAllOpenPrograms()) {
			if (p == program)
				return true;
		}

		return false;
	}

	/**
	 * Resolves a data type by name, handling common types and pointer types
	 *
	 * @param tool     The plugin tool to use for services
	 * @param dtm      The data type manager
	 * @param typeName The type name to resolve
	 * @return The resolved DataType, or null if not found
	 */
	public static DataType resolveDataType(PluginTool tool, Program program, DataTypeManager dtm, String typeName) {
		DataTypeManagerService dtms = resolveService(tool, program, DataTypeManagerService.class);
		DataTypeManager[] managers = dtms.getDataTypeManagers();
		DataType dt = null;

		List<DataTypeManager> managerList = new ArrayList<>();
		for (DataTypeManager manager : managers) {
			if (manager != dtm)
				managerList.add(manager);
		}
		managerList.addFirst(dtm);

		DataTypeParser parser = null;

		for (DataTypeManager manager : managerList) {
			try {
				parser = new DataTypeParser(manager, null, null, AllowedDataTypes.ALL);
				dt = parser.parse(typeName);
				if (dt != null) {
					return dt; // Found a successful parse, return
				}
			} catch (Exception e) {
				// Continue to next manager if this one fails
			}
		}

		// Fallback to int if we couldn't find it
		Msg.warn(GhidraUtils.class, "Unknown type: " + typeName + ", defaulting to int");
		return dtm.getDataType("/int");
	}

	/**
	 * Sets a comment at the specified address in the current program.
	 *
	 * @param tool            the plugin tool
	 * @param addressStr      the address as a string
	 * @param comment         the comment to set
	 * @param commentType     the type of comment (e.g., CodeUnit.PLATE_COMMENT)
	 * @param transactionName the name of the transaction for logging
	 * @return true if successful, false otherwise
	 */
	public static boolean setCommentAtAddress(PluginTool tool, String programName, String addressStr, String comment, CommentType commentType, String transactionName) {
		Program program = getProgramByName(tool, programName);
		if (program == null)
			return false;
		if (addressStr == null || addressStr.isEmpty() || comment == null)
			return false;

		AtomicBoolean success = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction(transactionName);
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					program.getListing().setComment(addr, commentType, comment);
					success.set(true);
				} catch (Exception e) {
					Msg.error(GhidraUtils.class, "Error setting " + transactionName.toLowerCase(), e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(GhidraUtils.class,
					"Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
		}

		return success.get();
	}
}
