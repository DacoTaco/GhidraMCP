package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

/**
 * Handler to get all references to a specific function by name.
 * Expects query parameters: name, offset, limit
 */
public final class GetFunctionXrefs extends Handler {
	public GetFunctionXrefs(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves cross-references to a function by its name.
	 * 
	 * @param functionName the name of the function to find references for
	 * @param offset       the starting index for pagination
	 * @param limit        the maximum number of results to return
	 * @return a string containing the references or an error message
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/function_xrefs")
    @McpTool(name = "function_xrefs", description = "Get all references to the specified function by name")
    public String getFunctionXrefs(@Param(name = "program", nullable=true) String programName, @Param(name = "name") String functionName,
            @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit
    ) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";
		if (functionName == null || functionName.isEmpty())
			return "Function name is required";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;

		try {
			List<String> refs = new ArrayList<>();
			FunctionManager funcManager = program.getFunctionManager();
			for (Function function : funcManager.getFunctions(true)) {
				if (function.getName().equals(functionName)) {
					Address entryPoint = function.getEntryPoint();
					ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

					while (refIter.hasNext()) {
						Reference ref = refIter.next();
						Address fromAddr = ref.getFromAddress();
						RefType refType = ref.getReferenceType();

						Function fromFunc = funcManager.getFunctionContaining(fromAddr);
						String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

						refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
					}
				}
			}

			if (refs.isEmpty()) {
				return "No references found to function: " + functionName;
			}

			return paginateList(refs, offset, limit);
		} catch (Exception e) {
			return "Error getting function references: " + e.getMessage();
		}
	}
}
