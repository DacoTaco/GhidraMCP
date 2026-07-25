package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Handler to list all functions in the current program.
 * Responds with a list of function names and their entry points.
 */
public final class Functions extends Handler {

    public Functions(PluginTool tool) {
        super(tool);
    }

	/**
	 * Searches for functions in the current program by name.
	 * Returns a paginated list of matching functions.
	 *
	 * @param searchTerm the term to search for in function names.
	 * @param offset     the pagination offset.
	 * @param limit      the maximum number of results to return.
	 * @return a string containing the results or an error message.
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method = HttpMethod.GET, path = "/searchFunctions")
    public String SearchFunctionsByName(@Param(name = "query") String searchTerm, @Param(name = "offset", nullable = true) Integer offset,
            							@Param(name = "limit", nullable = true) Integer limit, 
										@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) {
		return GetFunctions(searchTerm, null, offset, limit, programName);
	}

	/**
	 * Lists all functions in the current program.
	 *
	 * @return a string containing the names and entry points of all functions
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.GET, path = "/list_functions")
	public String ListFunctions(@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) {
		return GetFunctions(null, null, 0, null, programName);
	}

	/**
	 * Retrieves function details by address
	 *
	 * @param addressStr the address as a string
	 * @return a string containing function details or an error message
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method = HttpMethod.GET, path = "/get_function_by_address")
	public String GetFunctionByAddress(@Param(name = "address") String addressStr, 
									   @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) {
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		return GetFunctions(null, addressStr, 0, null, programName);
	}

	/**
	 * Generates a paginated response containing all function names in the current
	 * program.
	 *
	 * @param offset the starting index for pagination
	 * @param limit  the maximum number of function names to return
	 * @return a string containing the paginated list of function names
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.GET, path="/methods")
	public String GetMethods(@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName, 
							 @Param(name="offset", description="The starting index for pagination.", nullable=true) Integer offset, 
							 @Param(name="limit", description="The maximum number of function names to return.", nullable=true) Integer limit) {
		return GetFunctions(null, null,offset, limit, programName);
	}

	private String FormatFunction(Function func) {
		return String.format("%s(%s - %s): %s",
				func.getEntryPoint(),
				func.getBody().getMinAddress(),
				func.getBody().getMaxAddress(),
				func.getSignature());
	}

	/**
	 * Searches for functions in the current program by name.
	 * Returns a paginated list of matching functions.
	 *
	 * @param searchTerm the optional term to search for in function names.
	 * @param offset     the optional pagination offset.
	 * @param limit      the optional maximum number of results to return.
	 * @return a string containing the results or an error message.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/functions")
    @McpTool(name = "get_functions", description = "Get functions in the database, optionally filtering by name or address.")
	public String GetFunctions(@Param(name = "query", nullable = true, description = "The optionalterm to search for in function names.") String searchTerm, 
							   @Param(name = "address", nullable = true) String address,
							   @Param(name = "offset", nullable = true) Integer offset,
							   @Param(name = "limit", nullable = true) Integer limit, 
							   @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) {
		Program program = getProgramByName(programName);
		if (program == null)
			return "No program loaded";

		List<String> matches = new ArrayList<>();
		if (address != null && !address.isEmpty())
		{
			Address addr = program.getAddressFactory().getAddress(address);
			Function func = program.getFunctionManager().getFunctionAt(addr);

			if (func == null)
				return "No function found at address " + address;

			matches.add(FormatFunction(func));
		}
		else
		{
			for (Function func : program.getFunctionManager().getFunctions(true)) {
				String name = func.getName();

				if((searchTerm != null && !searchTerm.isEmpty()) && !name.toLowerCase().contains(searchTerm.toLowerCase()))
					continue;

				matches.add(FormatFunction(func));
			}
		}

		if (matches.isEmpty()) {
			return "No matching functions found";
		}

		Collections.sort(matches);
		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? matches.size() : limit;
		return paginateList(matches, offset, limit);
	}
}
