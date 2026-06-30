package com.lauriewired.handlers;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.reflections.Reflections;

import com.lauriewired.GhidraMCPPlugin;
import com.lauriewired.endpoints.ServerEndpoint;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.mcp.McpTool;
import com.lauriewired.mcp.McpToolFactory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;

public final class EndpointFactory {
    private final McpToolFactory mcpToolFactory;

    public EndpointFactory(McpToolFactory mcpFactory){
        this.mcpToolFactory = mcpFactory;
    }

    /**
     * Creates endpoint metadata.
     *
     * @param tool the PluginTool used to instantiate handlers. May be null when
     *             performing metadata generation only.
     */
    public List<ServerEndpoint> create(PluginTool tool) {
        List<ServerEndpoint> endpoints = new ArrayList<>();
        Reflections reflections = new Reflections("com.lauriewired.handlers");
        Set<Class<? extends Handler>> handlerClasses = reflections.getSubTypesOf(Handler.class);
        
        for (Class<? extends Handler> handlerClass : handlerClasses) {
            try {
                Constructor<? extends Handler> constructor = handlerClass.getConstructor(PluginTool.class);
                Handler handler = constructor.newInstance(tool);
                
                for (Method m : handlerClass.getDeclaredMethods()) {
                    HttpRoute route = m.getAnnotation(HttpRoute.class);
                    if (route == null) continue;

                    SyncToolSpecification specs = m.getAnnotation(McpTool.class) != null
                        ? mcpToolFactory.create(handler, m)
                        : null;
                    Msg.info(GhidraMCPPlugin.class, "Registered command handler: " + handlerClass.getSimpleName());
                    
                    endpoints.add(
                        new ServerEndpoint(
                            handler,
                            m,
                            route.method(),
                            route.path(), 
                            specs
                        )
                    );
                }

            } catch (NoSuchMethodException e) {
                Msg.error(GhidraMCPPlugin.class, "Handler " + handlerClass.getName() + " must define a constructor (PluginTool tool)");
            } catch (Exception e) {
                Msg.error(GhidraMCPPlugin.class, "Failed to register command handler: " + handlerClass.getName(), e);
            }
        }

        return endpoints;
    }
}