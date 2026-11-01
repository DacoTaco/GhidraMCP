package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.AddressUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Handler for adding tags to and removing tags from a function.
 */
public final class FunctionTags extends Handler {

    public FunctionTags(PluginTool tool) {
        super(tool);
    }

    @HttpRoute(method = HttpMethod.POST, path = "/addFunctionTags")
    @McpTool(name = "add_function_tags", description = "Add tags to the function containing an address.")
    public void AddFunctionTags(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address") String address,
            @Param(name = "tags", description = "Tag names") String[] tags) throws Exception {
        EditTags(programName, address, tags, true);
    }

    /**
     * Removes tags from the function at or containing an address. The tags
     * themselves stay in the program.
     */
    @HttpRoute(method = HttpMethod.POST, path = "/removeFunctionTags")
    @McpTool(name = "remove_function_tags", description = "Remove tags from the function containing an address.")
    public void RemoveFunctionTags(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "address") String address,
            @Param(name = "tags", description = "Tag names") String[] tags) throws Exception {
        EditTags(programName, address, tags, false);
    }

    private void EditTags(String programName, String address, String[] tags, boolean add) throws Exception {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }

        Function function = program.getFunctionManager().getFunctionContaining(AddressUtils.parseAddress(program, address));
        if (function == null) {
            throw new IllegalArgumentException("No function at or containing " + address);
        }

        // a Runnable can't throw checked exceptions, so the error is carried out of the Swing thread
        final AtomicReference<Exception> error = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(add ? "Add function tags" : "Remove function tags");
                boolean success = false;
                try {
                    for (String tag : tags) {
                        String name = tag.trim();
                        if (name.isEmpty()) {
                            continue;
                        }

                        if (add) {
                            function.addTag(name);
                        } else {
                            function.removeTag(name);
                        }
                    }
                    success = true;
                } catch (Exception e) {
                    error.set(e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            throw new Exception("Failed to execute edit function tags on Swing thread: " + e.getMessage(), e);
        }

        if (error.get() != null) {
            throw error.get();
        }
    }
}
