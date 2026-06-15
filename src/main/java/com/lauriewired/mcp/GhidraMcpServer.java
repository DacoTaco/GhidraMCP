package com.lauriewired.mcp;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.*;
import io.modelcontextprotocol.server.transport.*;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import java.util.List;
import java.io.IOException;

public class GhidraMcpServer {
    private final HttpServletStreamableServerTransportProvider transport;
    private Server jettyServer;
    private McpSyncServer mcpServer;

    private final int port;

    public GhidraMcpServer() {
        this(8081);
    }

    public GhidraMcpServer(int port) {
        this.port = port;

        //setup the MCP server transport
        this.transport = HttpServletStreamableServerTransportProvider
            .builder()
            .mcpEndpoint("/mcp")
            .build();

        McpSchema.ServerCapabilities serverCapabilities = McpSchema.ServerCapabilities
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
        registerTools();
        //mcpSyncServer.addTool(syncToolSpecification);
        //mcpSyncServer.addResource(syncResourceSpecification);
        //mcpSyncServer.addPrompt(syncPromptSpecification);

        //setup the jetty server to host the mcp server
        this.jettyServer = new Server(port);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        // Mount MCP servlet at /mcp
        context.addServlet(
            new ServletHolder(transport),
            "/mcp/*"
        );

        jettyServer.setHandler(context);
    }

    private void registerTools()
    {
        McpSchema.Tool tool = McpSchema.Tool
            .builder("ghidra-test")
            .description("A tool for interacting with Ghidra from MCP clients")
            .build();
        
        McpServerFeatures.SyncToolSpecification spec = McpServerFeatures.SyncToolSpecification
        .builder()
        .tool(tool)
        .callHandler((exchange, request) -> {

            return McpSchema.CallToolResult.builder()
                .content(List.of(
                    new McpSchema.TextContent("pong")
                ))
                .build();
        })
        .build();

        mcpServer.addTool(spec);
    }

    public void start(){
        try {
            jettyServer.start();
        } catch (Exception e) {
            throw new RuntimeException("Failed to start MCP Jetty server", e);
        }
    }

    public void stop(){
        try {
            if (jettyServer != null) {
                jettyServer.stop();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}