package com.lauriewired.handlers.get;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Handler to list all programs
 * Responds with a list of function names and their entry points.
 */
public final class Programs extends Handler {

    public Programs(PluginTool tool) {
        super(tool);
    }

    public record ProgramInformation(String Name, String Path, Boolean IsCurrent, String ExecutablePath, 
                                     String Language, String Compiler ){}

    private List<ProgramInformation> GetProjectFolderFiles(DomainFolder folder)
    {
        List<ProgramInformation> programs = new ArrayList<>();

        for(DomainFolder subFolder: folder.getFolders())
            programs.addAll(GetProjectFolderFiles(subFolder));

        for(DomainFile file : folder.getFiles())
            programs.add(new ProgramInformation(file.getName(), file.getPathname(), false, null, null, null));

        return programs;
    }

    public List<ProgramInformation> GetProjectFiles() throws Exception {

        Project project = tool.getProject();
        if (project == null) {
            throw new Exception("No project is currently open");
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        //if we ever want to filter on sub folders, do it here
        DomainFolder targetFolder = rootFolder;

        //todo: refactor. fetch all subfolders and for each subfolder, fetch the files and folders then add files of the subfolder
        //this should be done recursively with a DomainFolder as input and returning a list of ProgramInformation
        // List files in folder
        return GetProjectFolderFiles(targetFolder);
    }

    private List<ProgramInformation> GetOpenedPrograms()
    {
        List<Program> programs = getOpenPrograms();
        Program currentProgram = getProgramByName(null);
        if (programs == null || programs.isEmpty()) {
            return List.of();
        }

        List<ProgramInformation> openedPrograms = new ArrayList<>();
        for (Program prog : programs) {
            openedPrograms.add(new ProgramInformation(prog.getName(), prog.getDomainFile().getPathname(), prog == currentProgram,
                                                      prog.getExecutablePath() != null ? prog.getExecutablePath() : "",
                                                      prog.getLanguageID().getIdAsString(), 
                                                      prog.getCompilerSpec().getCompilerSpecID().getIdAsString()));
        }

        return openedPrograms;
    }

    /**
	 * Fetches all programs
	 *
	 * @return a list of programs.
	 */
	@HttpRoute(method = HttpMethod.GET, path = "/programs")
    @McpTool(name = "get_programs", description = "Get all programs in the current project, only showing opened programs by default")
    public List<ProgramInformation> ListPrograms(@Param(name = "opened", description="fetch opened programs only", nullable = true) Boolean opened) throws Exception {
        
        opened = opened == null ? true : opened;
        return opened 
            ? GetOpenedPrograms()
            : GetProjectFiles(); 
    }
}