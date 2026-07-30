package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.Comparator;
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
										@Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) 
										throws Exception {
		return String.join("\n", GetFunctions(searchTerm, null, offset, limit, programName).stream().map(info -> FormatFunction(info)).toList());
	}

	/**
	 * Lists all functions in the current program.
	 *
	 * @return a string containing the names and entry points of all functions
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method=HttpMethod.GET, path = "/list_functions")
	public String ListFunctions(@Param(name="program", description="optional program name to work with. normally kept empty to select active program.", nullable=true) String programName) 
								throws Exception {
		return String.join("\n", GetFunctions(null, null, 0, null, programName).stream().map(info -> FormatFunction(info)).toList());
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
									   @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName)
									   throws Exception {
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

		return String.join("\n", GetFunctions(null, addressStr, 0, null, programName).stream().map(info -> FormatFunction(info)).toList());
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
							 @Param(name="limit", description="The maximum number of function names to return.", nullable=true) Integer limit) throws Exception {
		return String.join("\n", GetFunctions(null, null,offset, limit, programName).stream().map(info -> FormatFunction(info)).toList());
	}

	private String FormatFunction(FunctionInformation func) {
		return String.format("%s(%s - %s): %s",
				func.Entrypoint,
				func.StartAddress,
				func.EndAddress,
				func.Signature);
	}

	public record FunctionInformation(String Entrypoint, String Name, String Signature, String StartAddress, String EndAddress){}

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
	public List<FunctionInformation> GetFunctions(@Param(name = "query", nullable = true, description = "The optionalterm to search for in function names.") String searchTerm, 
							   @Param(name = "address", nullable = true) String address,
							   @Param(name = "offset", nullable = true) Integer offset,
							   @Param(name = "limit", nullable = true) Integer limit, 
							   @Param(name = "program", description="optional program name to work with. normally kept empty to select active program.", nullable = true) String programName) 
							   throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception((programName == null || programName.isEmpty()) ? "No program loaded" : "No Program with name '" + programName + "is loaded");

		List<FunctionInformation> matches = new ArrayList<>();
		if (address != null && !address.isEmpty())
		{
			Address addr = program.getAddressFactory().getAddress(address);
			Function func = program.getFunctionManager().getFunctionAt(addr);

			if (func == null)
				throw new Exception("No function found at address " + address);

			matches.add(new FunctionInformation(func.getEntryPoint().toString(), func.getName(), func.getSignature().toString(), 
												func.getBody().getMinAddress().toString(), func.getBody().getMaxAddress().toString()));
		}
		else
		{
			for (Function func : program.getFunctionManager().getFunctions(true)) {
				String name = func.getName();

				if((searchTerm != null && !searchTerm.isEmpty()) && !name.toLowerCase().contains(searchTerm.toLowerCase()))
					continue;

				matches.add(new FunctionInformation(func.getEntryPoint().toString(), func.getName(), func.getSignature().toString(), 
							func.getBody().getMinAddress().toString(), func.getBody().getMaxAddress().toString()));
			}
		}

		if (matches.isEmpty()) {
			throw new Exception("No matching functions found");
		}

		matches.sort(Comparator.comparing(FunctionInformation::Entrypoint));
		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? matches.size() : limit;
		return paginateList(matches, offset, limit);
	}
}
