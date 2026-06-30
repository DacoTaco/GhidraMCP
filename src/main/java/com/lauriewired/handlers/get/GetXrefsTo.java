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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Handler to get all references to a specific address in the current program.
 * Example usage: /xrefs_to?address=0x00401000&offset=0&limit=100
 */
public final class GetXrefsTo extends Handler {
	/**
	 * Constructor for the GetXrefsTo handler.
	 *
	 * @param tool the Ghidra plugin tool
	 */
	public GetXrefsTo(PluginTool tool) {
		super(tool);
	}

	/**
	 * Retrieves cross-references to a specific address in the current program.
	 *
	 * @param addressStr the address to get references to
	 * @param offset     the offset for pagination
	 * @param limit      the maximum number of results to return
	 * @return a string representation of the references found
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/xrefs_to")
    @McpTool(name = "get_xrefs_to", description = "Get all references to the specified address (xref to)")
	public String getXrefsTo(@Param(name = "program", nullable = true) String programName, @Param(name = "address") String addressStr,
            				 @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		
		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();

			ReferenceIterator refIter = refManager.getReferencesTo(addr);

			List<String> refs = new ArrayList<>();
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				Address fromAddr = ref.getFromAddress();
				RefType refType = ref.getReferenceType();

				Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
				String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

				refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
			}

			return paginateList(refs, offset, limit);
		} catch (Exception e) {
			return "Error getting references to address: " + e.getMessage();
		}
	}
}
