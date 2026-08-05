package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.escapeString;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Handler for listing defined data in the current program.
 *
 * Example usage: GET /data?offset=0&limit=100
 */
public final class DefinedData extends Handler {

    /**
     * Constructs a new DefinedData handler.
     *
     * @param tool The PluginTool instance to use for accessing the current
     * program.
     */
    public DefinedData(PluginTool tool) {
        super(tool);
    }

    public record DataInformation(String Label, String Address, String Value) {

        public String OldFormat() {
            return String.format("%s -> %s : %s%n", Label, Address, Value);
        }
    }

    /**
     * Retrieves data associated with the specified label in the current
     * program.
     *
     * @param label The label to search for in the current program.
     * @return A string containing the address and value of the data defined at
     * that label, or an error message if the label is not found or no program
     * is loaded.
     * @deprecated Use {@link #GetDefinedData(String, Integer, Integer, String)}
     * instead for more flexible data retrieval.
     */
    @Deprecated(forRemoval = true)
    @HttpRoute(method = HttpMethod.GET, path = "/get_data_by_label")
    public String handle(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "label", description = "Exact symbol / label name.") String label) throws Exception {

        var data = GetDefinedData(label, null, null, programName);
        if (data.isEmpty()) {
            throw new Exception("No data found for label: " + label);
        }

        StringBuilder sb = new StringBuilder();
        for (DataInformation dataInfo : data) {
            sb.append(dataInfo.OldFormat());
        }

        return sb.toString();
    }

    /**
     * Lists defined data in the current program, paginated by offset and limit.
     *
     * @param label Optional label to search for in the current program.
     * @param offset The starting index for pagination.
     * @param limit The maximum number of items to return.
     * @return A list containing the address and value of the data defined at
     * that label, or an error message if the label is not found or no program
     * is loaded.
     */
    @HttpRoute(method = HttpMethod.GET, path = "/data")
    @McpTool(name = "list_data_items", description = "List defined data labels and their values with pagination, optional filtering by name.")
    public List<DataInformation> GetDefinedData(
            @Param(name = "label", description = "optional symbol / label name to search for.", nullable = true) String label,
            @Param(name = "offset", nullable = true) Integer offset,
            @Param(name = "limit", nullable = true) Integer limit,
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName)
            throws Exception {

        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("No program loaded");
        }

        List<DataInformation> dataList = new ArrayList<>();
        if (label != null && !label.isEmpty()) {
            SymbolTable st = program.getSymbolTable();
            SymbolIterator it = st.getSymbols(label);
            if (!it.hasNext()) {
                throw new Exception("Label not found: " + label);
            }

            while (it.hasNext()) {
                Symbol symbol = it.next();
                Data data = program.getListing().getDefinedDataAt(symbol.getAddress());
                String value = (data != null)
                        ? escapeString(String.valueOf(data.getDefaultValueRepresentation()))
                        : null;
                dataList.add(new DataInformation(label, symbol.getAddress().toString(), value));
            }
        } else {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    if (block.contains(data.getAddress())) {
                        String name = data.getLabel() != null ? data.getLabel() : null;
                        String value = data.getDefaultValueRepresentation();
                        dataList.add(new DataInformation(name, data.getAddress().toString(), value));
                    }
                }
            }
        }

        offset = (offset == null) ? 0 : offset;
        limit = (limit == null) ? 100 : limit;
        return paginateList(dataList, offset, limit);
    }
}
