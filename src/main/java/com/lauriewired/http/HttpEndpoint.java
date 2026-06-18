package com.lauriewired.http;

import java.lang.reflect.Method;

import org.eclipse.jetty.http.HttpMethod;

public final class HttpEndpoint {
    public final Object handler;
    public final Method method;
    public final HttpMethod httpMethod;
    public final String path;

    public HttpEndpoint(Object handler, Method method, HttpMethod httpMethod, String path) {
        this.handler = handler;
        this.method = method;
        this.httpMethod = httpMethod;
        this.path = path;
    }
}