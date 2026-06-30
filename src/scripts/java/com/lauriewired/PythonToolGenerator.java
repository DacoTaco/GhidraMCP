package com.lauriewired;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.endpoints.Param;
import com.lauriewired.endpoints.ParamLocation;
import com.lauriewired.endpoints.ServerEndpoint;

import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.Tool;

public final class PythonToolGenerator {

    public void generate(Path headerPath, Path footerPath, List<ServerEndpoint> endpoints, Path outputPath) throws IOException {

        String tools = endpoints.stream()
            .filter(e -> e.toolInformation.isPresent())
            .map(this::generateTool)
            .collect(Collectors.joining("\n\n"));

        String content = Files.readString(headerPath)
            + "\n\n"
            + """
            # ===============================
            # GENERATED MCP TOOLS
            # ===============================

            """
            + tools
            + Files.readString(footerPath);
        Files.writeString(outputPath,content);
    }

    private String generateTool(ServerEndpoint endpoint) {
        SyncToolSpecification specs = endpoint.toolInformation.orElse(null);
        if (specs == null)
            return "";

        Tool tool = specs.tool();
        Method method = endpoint.method;
        boolean isGet = endpoint.httpMethod == HttpMethod.GET;

        List<ParamInformation> required = new ArrayList<>();
        List<ParamInformation> optional = new ArrayList<>();
        List<ParamInformation> query = new ArrayList<>();

        ParamInformation body = null;
        boolean hasNullableProgram = false;

        for (Parameter p : method.getParameters()) {
            Param ann = p.getAnnotation(Param.class);
            if (ann == null) continue;

            ParamInformation info = new ParamInformation(
                ann.name(),
                ann.description(),
                p.getType(),
                ann.nullable(),
                ann.location() == ParamLocation.Body
            );

            if (info.nullable())
                optional.add(info);
            else
                required.add(info);

            if (info.body()) {
                body = info;
            } else {
                query.add(info);

                if ("program".equals(info.name()) && info.nullable()) {
                    hasNullableProgram = true;
                }
            }
        }

        StringBuilder sb = new StringBuilder();

        sb.append("@mcp.tool()\n");
        sb.append("def ")
            .append(tool.name())
            .append("(");

        sb.append(
            Stream.concat(required.stream(), optional.stream())
                .map(p -> {
                    String arg = p.name() + ": " + javaToPythonType(p.type());
                    if (p.nullable()) {
                        arg += " = " + defaultValue(p.name(), p.type());
                    }
                    return arg;
                })
                .collect(Collectors.joining(", "))
        );

        sb.append(") -> ")
            .append(javaToPythonType(method.getReturnType()))
            .append(":\n");

        sb.append("    \"\"\"\n    ")
            .append(tool.description().trim().replace("\n", "\n    "))
            .append("\n");

        boolean wroteArgs = false;
        for (ParamInformation p : Stream.concat(required.stream(), optional.stream()).toList()) {
            if (!p.description().isBlank()) {
                if (!wroteArgs) {
                    sb.append("\n    Args:\n");
                    wroteArgs = true;
                }

                sb.append("        ")
                    .append(p.name())
                    .append(": ")
                    .append(p.description())
                    .append("\n");
            }
        }

        sb.append("    \"\"\"\n");

        String path = endpoint.path.startsWith("/")
            ? endpoint.path.substring(1)
            : endpoint.path;

        boolean hasQuery = !query.isEmpty();

        String params = "{}";
        if (hasQuery) {
            String inner = query.stream()
                .map(p -> "\"" + p.name() + "\": " + p.name())
                .collect(Collectors.joining(", "));

            params = "{k: v for k, v in {"
                + inner
                + "}.items() if v is not None}";
        }

        if (hasNullableProgram) {
            params = "_with_program(" + params + ", program)";
            hasQuery = true;
        }

        sb.append("    return ");

        String call = isGet ? "safe_get" : "safe_post";

        sb.append(call)
            .append("(\"")
            .append(path)
            .append("\"");

        if (!isGet && body != null) {
            sb.append(", ").append(body.name());
            if (hasQuery) sb.append(", ").append(params);
        } else if (hasQuery) {
            sb.append(", ").append(params);
        }

        sb.append(")\n");

        return sb.toString();
    }

    /** Maps a Java type to a Python type annotation string. */
    private String javaToPythonType(Class<?> type) {
        if (type == String.class) return "str";
        if (type == int.class || type == Integer.class) return "int";
        if (type == long.class || type == Long.class) return "int";
        if (type == boolean.class || type == Boolean.class) return "bool";
        if (type == double.class || type == Double.class) return "float";
        if (type == float.class || type == Float.class) return "float";
        if (type.isArray()) return "list";
        if (java.util.List.class.isAssignableFrom(type)) return "list";
        return "str";
    }

    /** Returns the Python default literal for a nullable parameter. */
    private String defaultValue(String paramName, Class<?> type) {
        if ("program".equals(paramName)) return "\"\"";
        if ("offset".equals(paramName)) return "0";
        if ("limit".equals(paramName)) return "100";
        if (type == boolean.class || type == Boolean.class) return "False";
        return "None";
    }
}