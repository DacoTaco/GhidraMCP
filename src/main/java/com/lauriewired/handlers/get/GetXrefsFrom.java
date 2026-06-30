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
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/** Handler for getting cross-references from a specific address */
public final class GetXrefsFrom extends Handler {
	/**
	 * Constructor for the GetXrefsFrom handler.
	 * 
	 * @param tool The PluginTool instance to use for accessing the current program.
	 */
	public GetXrefsFrom(PluginTool tool) {
		super(tool);
	}

	/**
	 * Get references from a specific address in the current program.
	 * 
	 * @param addressStr The address to get references from.
	 * @param offset     The offset for pagination.
	 * @param limit      The maximum number of references to return.
	 * @return A string containing the references or an error message.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/xrefs_from")
    @McpTool(name = "get_xrefs_from", description = "Get all references from the specified address (xref from)")
	public String getXrefsFrom(@Param(name = "program", nullable = true) String programName, @Param(name = "address") String addressStr,
            				   @Param(name = "offset", nullable = true) Integer offset, @Param(name = "limit", nullable = true) Integer limit) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;

		try {
			Address addr = program.getAddressFactory().getAddress(addressStr);
			ReferenceManager refManager = program.getReferenceManager();

			Reference[] references = refManager.getReferencesFrom(addr);

			List<String> refs = new ArrayList<>();
			for (Reference ref : references) {
				Address toAddr = ref.getToAddress();
				RefType refType = ref.getReferenceType();

				String targetInfo = "";
				Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
				if (toFunc != null) {
					targetInfo = " to function " + toFunc.getName();
				} else {
					Data data = program.getListing().getDataAt(toAddr);
					if (data != null) {
						targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
					}
				}

				refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
			}

			return paginateList(refs, offset, limit);
		} catch (Exception e) {
			return "Error getting references from address: " + e.getMessage();
		}
	}
}
