package com.lauriewired.mcp;

import java.util.List;

import org.eclipse.jetty.servlet.ServletHolder;

import com.lauriewired.endpoints.ServerEndpoint;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;

public class GhidraMcpServer {
    private final HttpServletStreamableServerTransportProvider transport;
    private ServletHolder servlet;
    private McpSyncServer mcpServer;

    public GhidraMcpServer(List<ServerEndpoint> endpoints) {
        //setup the MCP server transport
        //because the context is set to /mcp, the transport will listen to everything under the context path
        this.transport = HttpServletStreamableServerTransportProvider
            .builder()
            .mcpEndpoint("/mcp")
            .build();

        ServerCapabilities serverCapabilities = ServerCapabilities
            .builder()
            .resources(true, true)
            .prompts(true)
            .tools(true)
            .build();

        // Create a server with custom configuration
        mcpServer = McpServer
            .sync(transport)
            .serverInfo("ghidra-mcp", "1.0.0")
            .capabilities(serverCapabilities)
            .build();

        // Register tools, resources, and prompts
        //mcpSyncServer.addTool(syncToolSpecification);
        //mcpSyncServer.addResource(syncResourceSpecification);
        //mcpSyncServer.addPrompt(syncPromptSpecification);

        // Create servlet
        servlet = new ServletHolder(transport);
        for (ServerEndpoint endpoint : endpoints)
        {
            if(endpoint == null || endpoint.toolInformation.isEmpty())
                continue;

            mcpServer.addTool(endpoint.toolInformation.get());
        }
    }

    public ServletHolder getServletHolder(){
        return servlet;
    }
}