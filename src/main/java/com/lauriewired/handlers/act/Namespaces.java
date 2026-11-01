package com.lauriewired.handlers.act;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.NamespacesUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

/**
 * Handler for editing namespaces and classes.
 */
public final class Namespaces extends Handler {

    /**
     * Constructor for the Namespaces handler.
     *
     * @param tool the PluginTool instance to interact with Ghidra
     */
    public Namespaces(PluginTool tool) {
        super(tool);
    }

    /**
     * Renames a namespace or class. Ghidra refuses the rename when the parent
     * already has a namespace or class with the new name.
     *
     * @param programName the program to work with
     * @param oldPath the full path of the namespace, e.g. "A::B"
     * @param newName the new name, without parent path
     * @throws Exception when the namespace could not be renamed
     */
    @HttpRoute(method = HttpMethod.POST, path = "/renameNamespace")
    @McpTool(name = "rename_namespace", description = "Rename a namespace or class, it stays in the same parent.")
    public void renameNamespace(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "old", description = "Full path, e.g. 'A::B'.") String oldPath,
            @Param(name = "new", description = "New name, without the parent path.") String newName)
            throws Exception {
        Program program = getProgramByName(programName);
        if (program == null) {
            throw new Exception("Program not found");
        }
        if (newName.contains("::")) {
            throw new IllegalArgumentException("The new name must not contain '::'");
        }

        Namespace namespace = NamespacesUtils.FindNamespace(program, oldPath);
        if (namespace == null || namespace.isGlobal()) {
            throw new IllegalArgumentException("Namespace '" + oldPath + "' not found");
        }

        // a Runnable can't throw checked exceptions, so the error is carried out of the Swing thread
        final AtomicReference<Exception> error = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename namespace");
                boolean success = false;
                try {
                    namespace.getSymbol().setName(newName.trim(), SourceType.USER_DEFINED);
                    success = true;
                } catch (Exception e) {
                    Msg.error(this, "Rename namespace error", e);
                    error.set(e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename namespace on Swing thread", e);
            throw new Exception("Failed to execute rename namespace on Swing thread: " + e.getMessage(), e);
        }

        if (error.get() != null) {
            throw error.get();
        }
    }
}
