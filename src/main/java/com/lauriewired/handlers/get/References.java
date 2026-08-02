package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import static com.lauriewired.util.ParseUtils.paginateList;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

/**
 * Handler to get all references to a specific address or function by name.
 */
public final class References extends Handler {

    public References(PluginTool tool) {
        super(tool);
    }

    public record ReferenceInfo(String Address, String Function, String Data, String ReferenceType) {

        public String OldFormat() {
            String info = Function == null ? Data : Function;
            return String.format("From %s%s [%s]", Address, info, ReferenceType);
        }
    }

    private Address ResolveTarget(String target, Program program) throws Exception {
        Address addr = program.getAddressFactory().getAddress(target);
        if (addr != null) {
            return addr;
        }

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (!func.getName().toLowerCase().equals(target.toLowerCase())) {
                continue;
            }

            return func.getEntryPoint();
        }

        throw new Exception("Could not find target: " + target);
    }

    /**
     * Retrieves cross-references to a specific address in the current program.
     *
     * @param target	the address or function name to get references to
     * @param offset the offset for pagination
     * @param limit the maximum number of results to return
     * @return a string representation of the references found
     * @deprecated This method works, but was merged into
     * {@link #GetReferencesTo(String, String, Integer, Integer)} instead
     */
    @HttpRoute(method = HttpMethod.GET, path = "/xrefs_to")
    @Deprecated(forRemoval = true)
    public List<String> getXrefsTo(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address", description = "Target address in hex format (e.g. 0x1400010a0).") String addressStr,
            @Param(name = "offset", nullable = true, description = "Pagination offset (default: 0).") Integer offset,
            @Param(name = "limit", nullable = true, description = "Maximum number of references to return (default: 100).") Integer limit)
            throws Exception {
        return GetReferencesTo(addressStr, programName, offset, limit).stream().map(info -> info.OldFormat()).toList();
    }

    /**
     * Get references from a specific address in the current program.
     *
     * @param addressStr The address to get references from.
     * @param offset The offset for pagination.
     * @param limit The maximum number of references to return.
     * @deprecated This method works, but was merged into
     * {@link #GetReferencesFrom(String, String, Integer, Integer)} instead
     * @return A string containing the references or an error message.
     */
    @HttpRoute(method = HttpMethod.GET, path = "/xrefs_from")
    @Deprecated(forRemoval = true)
    public List<String> getXrefsFrom(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address", description = "Source address in hex format (e.g. 0x1400010a0).") String addressStr,
            @Param(name = "offset", nullable = true, description = "Pagination offset (default: 0).") Integer offset,
            @Param(name = "limit", nullable = true, description = "Maximum number of references to return (default: 100).") Integer limit)
            throws Exception {
        return GetReferencesFrom(addressStr, programName, offset, limit).stream().map(info -> info.OldFormat()).toList();
    }

    /**
     * Retrieves cross-references to a specific address in the current program.
     *
     * @param target	the address or function name to get references to
     * @param offset the offset for pagination
     * @param limit the maximum number of results to return
     * @return a string representation of the references found
     */
    @HttpRoute(method = HttpMethod.GET, path = "/references/to")
    @McpTool(name = "get_xrefs_to", description = "Get all references to the specified address or function (xref to)")
    public List<ReferenceInfo> GetReferencesTo(@Param(name = "target", description = "Target address(in hex format,e.g. 0x1400010a0) or function name.") String target,
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "offset", nullable = true, description = "Pagination offset (default: 0).") Integer offset,
            @Param(name = "limit", nullable = true, description = "Maximum number of references to return (default: 100).") Integer limit)
            throws Exception {
        if (target == null || target.isEmpty()) {
            throw new Exception("Target address or function name is required");
        }

        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception((programName == null || programName.isEmpty()) ? "No program loaded" : "No Program with name '" + programName + "is loaded");
        }

        try {
            Address addr = ResolveTarget(target, program);
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);

            List<ReferenceInfo> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function toFunc = program.getFunctionManager().getFunctionAt(fromAddr);
                Data data = program.getListing().getDataAt(fromAddr);
                refs.add(new ReferenceInfo(fromAddr.toString(),
                        toFunc == null ? null : toFunc.getName(),
                        data == null ? null : (data.getLabel() != null ? data.getLabel() : data.getPathName()),
                        refType.getName()));
            }

            offset = (offset == null) ? 0 : offset;
            limit = (limit == null) ? 100 : limit;
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            throw new Exception("Error getting references to target: " + target + ". " + e.getMessage());
        }
    }

    /**
     * Get references from a specific address in the current program.
     *
     * @param target	the address or function name to get references to
     * @param offset The offset for pagination.
     * @param limit The maximum number of references to return.
     * @return A string containing the references or an error message.
     */
    @HttpRoute(method = HttpMethod.GET, path = "/references/from")
    @McpTool(name = "get_xrefs_from", description = "Get all references from the specified address or function (xref from)")
    public List<ReferenceInfo> GetReferencesFrom(@Param(name = "target", description = "Target address(in hex format,e.g. 0x1400010a0) or function name.") String target,
            @Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "offset", nullable = true, description = "Pagination offset (default: 0).") Integer offset,
            @Param(name = "limit", nullable = true, description = "Maximum number of references to return (default: 100).") Integer limit)
            throws Exception {
        if (target == null || target.isEmpty()) {
            throw new Exception("Target address or function name is required");
        }

        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Target address or function name is required");
        }

        try {
            Address addr = ResolveTarget(target, program);
            Reference[] references = program.getReferenceManager().getReferencesFrom(addr);

            List<ReferenceInfo> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                Data data = program.getListing().getDataAt(toAddr);
                refs.add(new ReferenceInfo(toAddr.toString(),
                        toFunc == null ? null : toFunc.getName(),
                        data == null ? null : (data.getLabel() != null ? data.getLabel() : data.getPathName()),
                        refType.getName()));
            }

            offset = (offset == null) ? 0 : offset;
            limit = (limit == null) ? 100 : limit;
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            throw new Exception("Error getting references from target: " + target + ". " + e.getMessage());
        }
    }
}
