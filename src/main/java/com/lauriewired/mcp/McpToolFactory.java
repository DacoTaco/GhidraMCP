package com.lauriewired.mcp;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.lauriewired.endpoints.ArgumentBinder;
import com.lauriewired.endpoints.Param;
import static com.lauriewired.util.ParseUtils.mcpError;
import static com.lauriewired.util.ParseUtils.mcpSuccess;

import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.Tool;

public final class McpToolFactory {

    private final ArgumentBinder argumentBinder;

    public McpToolFactory(ArgumentBinder binder){
        this.argumentBinder = binder;
    }

    public SyncToolSpecification create(Object handler, Method method) {

        McpTool annotation = method.getAnnotation(McpTool.class);
        if (annotation == null)
            throw new IllegalArgumentException("Method is not annotated with @McpTool: " + method);

        Tool tool = Tool.builder(annotation.name(), createSchema(method))
            .description(annotation.description())
            .build();

        return SyncToolSpecification.builder()
            .tool(tool)
            .callHandler((exchange, request) -> {

                try {
                    return mcpSuccess(method.invoke(handler, argumentBinder.bind(request, method)));
                }
                catch (InvocationTargetException e) {
                    return mcpError(e.getCause().getMessage());
                }
                catch (Exception e) {
                    return mcpError(e.getMessage());
                }

            })
            .build();
    }

    private Map<String, Object> createSchema(Method method) {
        Parameter[] parameters = method.getParameters();

        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("properties", createProperties(parameters));

        List<String> required = createRequired(parameters);
        if (!required.isEmpty())
            schema.put("required", required);

        return schema;
    }

    private Map<String, Object> createProperties(Parameter[] parameters) {
        Map<String, Object> properties = new HashMap<>();

        for (Parameter parameter : parameters) {

            Param param = parameter.getAnnotation(Param.class);
            if (param == null)
                continue;

            properties.put(
                param.name(),
                createPropertySchema(parameter.getType(), new HashSet<>())
            );
        }

        return properties;
    }

    private Map<String, Object> createPropertySchema(Class<?> type, Set<Class<?>> visited) {
        Map<String, Object> schema = new HashMap<>();

        if (type == null) {
            schema.put("type", "object");
            return schema;
        }

        // primitives
        if (type == String.class) {
            schema.put("type", "string");
            return schema;
        }

        if (type == int.class || type == Integer.class ||
            type == long.class || type == Long.class) {
            schema.put("type", "integer");
            return schema;
        }

        if (type == boolean.class || type == Boolean.class) {
            schema.put("type", "boolean");
            return schema;
        }

        if (type == double.class || type == Double.class ||
            type == float.class || type == Float.class) {
            schema.put("type", "number");
            return schema;
        }

        // enums
        if (type.isEnum()) {
            schema.put("type", "string");
            schema.put("enum",
                Arrays.stream(type.getEnumConstants())
                    .map(Object::toString)
                    .toList()
            );
            return schema;
        }

        // arrays
        if (type.isArray()) {
            schema.put("type", "array");
            schema.put("items", createPropertySchema(type.getComponentType(), visited));
            return schema;
        }

        // prevent cycles
        if (visited.contains(type)) {
            schema.put("type", "object");
            schema.put("description", "recursive reference");
            return schema;
        }

        visited.add(type);

        // object
        schema.put("type", "object");
        Map<String, Object> props = new HashMap<>();
        for (Field field : type.getDeclaredFields()) {
            props.put(field.getName(), createPropertySchema(field.getType(), visited));
        }

        schema.put("properties", props);
        visited.remove(type);
        return schema;
    }

    private List<String> createRequired(Parameter[] parameters) {
        List<String> required = new ArrayList<>();

        for (Parameter parameter : parameters) {

            Param param = parameter.getAnnotation(Param.class);
            if (param == null)
                continue;

            if (!param.nullable())
                required.add(param.name());
        }

        return required;
    }
}