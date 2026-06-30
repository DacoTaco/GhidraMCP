package com.lauriewired;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.lauriewired.endpoints.ArgumentBinder;
import com.lauriewired.endpoints.ServerEndpoint;
import com.lauriewired.handlers.EndpointFactory;
import com.lauriewired.mcp.McpToolFactory;

public final class GeneratePythonMain {

    public static void main(String[] args) throws Exception {

        if (args.length != 3) {
            System.err.println("Usage: GeneratePythonMain <header.py> <footer.py> <output.py>");
            System.exit(1);
        }

        System.out.println(">>> Generator STARTED");

        Path headerPath = Path.of(args[0]);
        Path footerPath = Path.of(args[1]);
        Path outputPath = Path.of(args[2]);

        if (!Files.exists(headerPath)) {
            throw new IllegalArgumentException("Header file not found: " + headerPath);
        }

        if (!Files.exists(footerPath)) {
            throw new IllegalArgumentException("Footer file not found: " + footerPath);
        }

        Files.createDirectories(outputPath.getParent());

        EndpointFactory endpointFactory = new EndpointFactory(new McpToolFactory(new ArgumentBinder()));
        List<ServerEndpoint> endpoints = endpointFactory.create(null);

        System.out.println(">>> Endpoints discovered: " + endpoints.size());

        PythonToolGenerator generator = new PythonToolGenerator();
        generator.generate(headerPath, footerPath, endpoints, outputPath);

        System.out.println("Generated Python client: " + outputPath.toAbsolutePath());
    }
}