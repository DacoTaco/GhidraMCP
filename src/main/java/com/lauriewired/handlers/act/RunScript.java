package com.lauriewired.handlers.act;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.util.GhidraUtils;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GhidraScriptService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Handler for running a script known to the Ghidra script manager.
 */
public final class RunScript extends Handler {

    public RunScript(PluginTool tool) {
        super(tool);
    }

    /**
     * Runs a script from the script manager's script directories and returns its
     * output. If the script is not found, the script list is refreshed and the
     * lookup is retried once, so newly added scripts can be picked up.
     */
    @HttpRoute(method = HttpMethod.POST, path = "/runScript")
    @McpTool(name = "run_script", description = "Run a script from the Ghidra script manager and return its output log. Scripts that prompt for input read their answers from args.")
    public String RunScript(@Param(name = "program", description = "optional program name to work with. normally kept empty to select active program.", nullable = true) String programName,
            @Param(name = "name", description = "Script file name, e.g. HelloWorldScript.java. Defaults to .java if no extension is given.") String scriptName,
            @Param(name = "args", description = "Arguments passed to the script", nullable = true) String[] args) throws Exception {
        if (GhidraScriptUtil.getBundleHost() == null) {
            throw new Exception("Script manager is not available");
        }

        // scripts can run without a program, so only a named program has to exist
        Program program = getProgramByName(programName);
        if (program == null && programName != null && !programName.isEmpty()) {
            throw new Exception("Program not found");
        }

        ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(scriptName);
        if (scriptFile == null) {
            refreshScriptList(program);
            scriptFile = GhidraScriptUtil.findScriptByName(scriptName);
        }

        if (scriptFile == null) {
            throw new IllegalArgumentException("Script not found: " + scriptName);
        }

        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
        if (provider == null) {
            throw new Exception("No script provider for " + scriptFile.getName());
        }

        StringWriter log = new StringWriter();
        PrintWriter writer = new PrintWriter(log, true);
        GhidraScript script = provider.getScriptInstance(scriptFile, writer);
        if (args != null) {
            script.setScriptArgs(args);
        }

        ProgramLocation location = null;
        if (program != null) {
            CodeViewerService codeViewer = GhidraUtils.resolveService(tool, program, CodeViewerService.class);
            if (codeViewer != null && codeViewer.getCurrentLocation() != null
                    && codeViewer.getCurrentLocation().getProgram() == program) {
                location = codeViewer.getCurrentLocation();
            }
        }

        GhidraState state = new GhidraState(tool, tool.getProject(), program, location, null, null);
        try {
            script.execute(state, new ScriptControls(writer, writer, false, TaskMonitor.DUMMY));
        } catch (Exception e) {
            writer.flush();
            throw new Exception("Script " + scriptFile.getName() + " failed: " + e + "\n" + log, e);
        }

        writer.flush();
        return log.toString();
    }

    private void refreshScriptList(Program program) throws Exception {
        GhidraScriptService service = GhidraUtils.resolveService(tool, program, GhidraScriptService.class);
        if (service == null) {
            return;
        }

        try {
            SwingUtilities.invokeAndWait(service::refreshScriptList);
        } catch (InterruptedException | InvocationTargetException e) {
            throw new Exception("Failed to refresh script list on Swing thread: " + e.getMessage(), e);
        }
    }
}
