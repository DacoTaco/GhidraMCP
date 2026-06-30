package com.lauriewired.endpoints;

import java.lang.reflect.Method;
import java.util.Optional;

import org.eclipse.jetty.http.HttpMethod;

import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;

public final class ServerEndpoint {
    public final Object handler;
    public final Method method;
    public final HttpMethod httpMethod;
    public final String path;
    public final Optional<SyncToolSpecification> toolInformation;

    public ServerEndpoint(Object handler, Method method, HttpMethod httpMethod, String path, SyncToolSpecification toolInformation) {
        this.handler = handler;
        this.method = method;
        this.httpMethod = httpMethod;
        this.path = path;
        this.toolInformation = Optional.ofNullable(toolInformation);
    }

    public ServerEndpoint(Object handler, Method method, HttpMethod httpMethod, String path) {
        this(handler, method, httpMethod, path, null);
    }
}