package com.lauriewired.handlers.get;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.stream.StreamSupport;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Program;

/**
 * Handler to read function tags.
 */
public final class FunctionTags extends Handler {

    public FunctionTags(PluginTool tool) {
        super(tool);
    }

    public record TagInformation(String Name, String Comment, int Count) {}

    /**
     * Lists the function tags with their use count. When an address or function
     * name is given, only the tags of that function are listed.
     *
     * @param programName the program to work with
     * @param address optional address inside the function
     * @param functionName optional function name, used when no address is given
     * @param offset the pagination offset
     * @param limit the maximum number of tags to return
     * @return the tags, sorted by name
     */
    @HttpRoute(method = HttpMethod.GET, path = "/tags")
    @McpTool(name = "get_tags", description = "List function tags with their use count, or only those of one function.")
    public List<TagInformation> listTags(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address", nullable = true) String address,
            @Param(name = "functionName", nullable = true) String functionName,
            @Param(name = "offset", nullable = true) Integer offset,
            @Param(name = "limit", nullable = true) Integer limit) throws Exception {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        FunctionTagManager tagManager = program.getFunctionManager().getFunctionTagManager();
        Collection<? extends FunctionTag> foundTags;
        if (address != null && !address.isEmpty()) {
            Function function = program.getFunctionManager().getFunctionContaining(AddressUtils.parseAddress(program, address));
            if (function == null) {
                throw new IllegalArgumentException("No function at or containing " + address);
            }
            foundTags = function.getTags();
        } else if (functionName != null && !functionName.isEmpty()) {
            Function function = StreamSupport
                    .stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
                    .filter(f -> f.getName().equals(functionName) || f.getName(true).equals(functionName))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Function '" + functionName + "' not found"));
            foundTags = function.getTags();
        } else {
            foundTags = tagManager.getAllFunctionTags();
        }

        List<TagInformation> tags = foundTags
                .stream()
                .map(tag -> new TagInformation(tag.getName(), tag.getComment(), tagManager.getUseCount(tag)))
                .sorted(Comparator.comparing(TagInformation::Name))
                .toList();

        return paginateList(tags, offset == null ? 0 : offset, limit == null ? tags.size() : limit);
    }
}
