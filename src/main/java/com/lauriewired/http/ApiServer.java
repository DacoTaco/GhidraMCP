package com.lauriewired.http;

import java.io.IOException;
import java.util.List;

import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.servlet.ServletHolder;

import com.google.gson.Gson;
import com.lauriewired.endpoints.ArgumentBinder;
import com.lauriewired.endpoints.ServerEndpoint;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ApiServer extends HttpServlet {

    private final List<ServerEndpoint> endpoints;
    private final ArgumentBinder binder;
    private final Gson gson = new Gson();
    private final ServletHolder servlet = new ServletHolder(this);

    public ApiServer(ArgumentBinder binder, List<ServerEndpoint> endpointInformation) {
        this.endpoints = endpointInformation;
        this.binder = binder;
    }

    public ServletHolder getServletHolder() {
        return servlet;
    }

    private void writeResponse(HttpServletResponse resp, Object result) throws IOException {
        resp.setStatus(200);
        if (result == null) {
            resp.getWriter().write("");
            return;
        }

        Class<?> type = result.getClass();

        // --- primitives / boxed primitives ---
        if (type == String.class
                || type == Integer.class
                || type == Long.class
                || type == Boolean.class
                || type == Double.class
                || type == Float.class
                || type == Short.class
                || type == Byte.class
                || type.isPrimitive()) {

            resp.setContentType("text/plain");
            resp.getWriter().write(String.valueOf(result));
            return;
        }

        // --- everything else → JSON ---
        resp.setContentType("application/json");
        resp.getWriter().write(gson.toJson(result));
    }
    
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        String path = req.getRequestURI();
        ServerEndpoint match = null;

        for (ServerEndpoint ep : endpoints) {
            if (ep.httpMethod != HttpMethod.fromString(req.getMethod()) || !ep.path.equals(path))
                continue;

            match = ep;
            break;
        }

        if (match == null) {
            resp.setStatus(404);
            resp.getWriter().write("Not Found");
            return;
        }

        try {
            Object[] args = binder.bind(req, match.method);
            writeResponse(resp, match.method.invoke(match.handler, args));

        } catch (IllegalArgumentException e) {
            resp.setStatus(400);
            resp.getWriter().write(e.getMessage());

        } catch (Exception e) {
            resp.setStatus(500);
            resp.getWriter().write("Internal Server Error: " + e.getMessage());
        }
    }
}