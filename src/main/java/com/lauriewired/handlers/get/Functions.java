package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
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
     * @param offset the pagination offset.
     * @param limit the maximum number of results to return.
	 * @return a string containing the results or an error message.
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
	@HttpRoute(method = HttpMethod.GET, path = "/searchFunctions")
    public String SearchFunctionsByName(@Param(name = "query") String searchTerm, @Param(name = "offset", nullable = true) Integer offset,
            							@Param(name = "limit", nullable = true) Integer limit, 
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName)
										throws Exception {
        return String.join("\n", GetFunctions(searchTerm, null, offset, limit, programName, null, null).stream().map(info -> FormatFunction(info)).toList());
	}

	/**
	 * Lists all functions in the current program.
	 *
	 * @return a string containing the names and entry points of all functions
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
    @HttpRoute(method = HttpMethod.GET, path = "/list_functions")
    public String ListFunctions(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName)
								throws Exception {
        return String.join("\n", GetFunctions(null, null, 0, null, programName, null, null).stream().map(info -> FormatFunction(info)).toList());
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
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName)
									   throws Exception {
		if (addressStr == null || addressStr.isEmpty())
			return "Address is required";

        return String.join("\n", GetFunctions(null, addressStr, 0, null, programName, null, null).stream().map(info -> FormatFunction(info)).toList());
	}

	/**
	 * Generates a paginated response containing all function names in the current
	 * program.
	 *
	 * @param offset the starting index for pagination
     * @param limit the maximum number of function names to return
	 * @return a string containing the paginated list of function names
	 * @deprecated This method works, but was merged into {@link #GetFunctions(String)} instead
	 */
	@Deprecated(forRemoval = true)
    @HttpRoute(method = HttpMethod.GET, path = "/methods")
    public String GetMethods(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "offset", description = "The starting index for pagination.", nullable = true) Integer offset,
            @Param(name = "limit", description = "The maximum number of function names to return.", nullable = true) Integer limit) throws Exception {
        return String.join("\n", GetFunctions(null, null, offset, limit, programName, null, null).stream().map(info -> FormatFunction(info)).toList());
	}

	private String FormatFunction(FunctionInformation func) {
		return String.format("%s(%s - %s): %s",
				func.Entrypoint,
				func.StartAddress,
				func.EndAddress,
				func.Signature);
	}

    public record FunctionInformation(String Entrypoint, String Name, String Signature, String StartAddress, String EndAddress, List<String> Tags) {}

	/**
	 * Searches for functions in the current program by name.
	 * Returns a paginated list of matching functions.
	 *
     * @param searchTerm the optional name filter: a substring, a wildcard
     * pattern or a /regex/.
     * @param address the optional entry point of a single function.
     * @param offset the optional pagination offset.
     * @param limit the optional maximum number of results to return.
     * @param tags the optional tags to filter by.
     * @param namespace only functions directly in this namespace, "global" for
     * the global namespace.
     * @return the matching functions.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/functions")
    @McpTool(name = "get_functions", description = "Get functions in the database, optionally filtering by name, address, tags or namespace.")
    public List<FunctionInformation> GetFunctions(@Param(name = "query", nullable = true, description = "The optional term to search for in function names. Accepts text, wildcards and regex.") String searchTerm,
							   @Param(name = "address", nullable = true) String address,
							   @Param(name = "offset", nullable = true) Integer offset,
							   @Param(name = "limit", nullable = true) Integer limit, 
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "tag", nullable = true, description = "Only functions that have all these tags, e.g. ['cov:lobby', 'lib:game'].") String[] tags,
            @Param(name = "namespace", nullable = true, description = "Only functions directly in this namespace, e.g. 'TCameraCtrl' or 'A::B'. Use 'global' for functions without a namespace.") String namespace)
							   throws Exception {
		Program program = getProgramByName(programName);
		if (program == null)
			throw new Exception((programName == null || programName.isEmpty()) ? "No program loaded" : "No Program with name '" + programName + "is loaded");

        List<Function> matches = new ArrayList<>();
        if (address != null && !address.isEmpty()) {
			Address addr = AddressUtils.parseAddress(program, address);
			Function func = program.getFunctionManager().getFunctionAt(addr);

			if (func == null)
				throw new Exception("No function found at address " + address);

            matches.add(func);
		}
		else
		{
            // case insensitive name filter: "/regex/", a wildcard pattern with '*' and '?' that must match
            // the whole name, or plain text that may match anywhere in the name
            Pattern pattern = null;
            if (searchTerm != null && !searchTerm.isEmpty()) {
                String regex;
                if (searchTerm.length() > 2 && searchTerm.startsWith("/") && searchTerm.endsWith("/")) {
                    regex = searchTerm.substring(1, searchTerm.length() - 1);
                } else if (searchTerm.indexOf('*') < 0 && searchTerm.indexOf('?') < 0) {
                    regex = Pattern.quote(searchTerm);
                } else {
                    StringBuilder wildcard = new StringBuilder("^");
                    for (char c : searchTerm.toCharArray()) {
                        switch (c) {
                            case '*' ->
                                wildcard.append(".*");
                            case '?' ->
                                wildcard.append('.');
                            default ->
                                wildcard.append(Pattern.quote(String.valueOf(c)));
                        }
                    }
                    regex = wildcard.append('$').toString();
                }
                // an invalid regex throws PatternSyntaxException, an IllegalArgumentException
                pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            }

            boolean filterNamespace = namespace != null && !namespace.isBlank();
            List<String> requiredTags = (tags == null || tags.length == 0) ? null : Arrays.asList(tags);

			for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (pattern != null && !pattern.matcher(func.getName()).find())
                    continue;

                if (filterNamespace && !func.getParentNamespace().getName(true).equalsIgnoreCase(namespace.trim()))
					continue;

                if (requiredTags != null) {
                    Set<String> names = func.getTags()
                            .stream()
                            .map(FunctionTag::getName).collect(Collectors.toSet());
                    if (!names.containsAll(requiredTags))
                        continue;
                }

                matches.add(func);
			}
		}

		if (matches.isEmpty()) {
			throw new Exception("No matching functions found");
		}

        matches.sort(Comparator.comparing(func -> func.getEntryPoint().toString()));
		offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? matches.size() : limit;
        return paginateList(matches, offset, limit)
                .stream()
                .map(func -> new FunctionInformation(func.getEntryPoint().toString(), func.getName(true), func.getSignature().toString(),
                        func.getBody().getMinAddress().toString(), func.getBody().getMaxAddress().toString(),
                        func.getTags().stream().map(FunctionTag::getName).sorted().toList()))
                .toList();
	}
}
