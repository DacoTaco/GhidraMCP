package com.lauriewired.http;

import java.io.BufferedReader;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import jakarta.servlet.http.HttpServletRequest;

public final class HttpArgumentBinder {

    private final Gson gson = new Gson();

    public Object[] bind(HttpServletRequest req, Method method){
        String contentType = req.getContentType();
        boolean isJson = contentType != null && contentType.toLowerCase().startsWith("application/json");
        String bodyContent = readBody(req);

        if(isJson && (bodyContent == null || bodyContent.isEmpty()))
            throw new IllegalArgumentException("Request body should be filled in when json request");

        Map<String, Object> args = new HashMap<>();
        for (Map.Entry<String, String[]> entry : req.getParameterMap().entrySet()) {
            String[] values = entry.getValue();

            if (values == null || values.length == 0) {
                args.put(entry.getKey(), null);
            } else if (values.length == 1) {
                args.put(entry.getKey(), values[0]);
            } else {
                args.put(entry.getKey(), values);
            }
        }

        return bindArguments(args, method, bodyContent, isJson);
    }

    public Object[] bind(CallToolRequest request, Method method){
        return bindArguments(request.arguments(), method, null, false);
    }

    private Object[] bindArguments(Map<String, Object> parameters, Method method, String bodyContent, boolean isJson) {
        Parameter[] params = method.getParameters();
        Object[] args = new Object[params.length];

        for (int i = 0; i < params.length; i++) {
            Parameter p = params[i];

            Param annotation = p.getAnnotation(Param.class);
            if (annotation == null) {
                args[i] = null;
                continue;
            }

            //this is also HTTP only, with MCP it can only fetch it from request.arguments().get("class_name")
            if ((bodyContent != null) && (annotation.location() == ParamLocation.Body || (isJson && annotation.location() == ParamLocation.Auto))) {
                Class<?> type = p.getType();

                if (isSimpleType(type))
                    args[i] = convert(bodyContent, type);
                else if (!isJson)
                    throw new IllegalStateException("Complex body parameters require application/json");
                else
                    args[i] = gson.fromJson(bodyContent, p.getParameterizedType());

                continue;
            }

            String key = annotation.name();
            Object value = parameters.get(key);

            if (value == null || isEmpty(value)) {
                if (!annotation.nullable())
                    throw new IllegalArgumentException("Missing required param: " + key);

                args[i] = value;
            } else {
                args[i] = convert(value, p.getType());
            }
        }

        return args;
    }

    private String readBody(HttpServletRequest req) {
        try (BufferedReader br = req.getReader()) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean isEmpty(Object value) {
        if (value == null)
            return true;

        if (value instanceof String s)
            return s.isBlank(); // or isEmpty()

        if (value instanceof Collection<?> c)
            return c.isEmpty();

        if (value instanceof Map<?, ?> m)
            return m.isEmpty();

        if (value.getClass().isArray())
            return Array.getLength(value) == 0;

        return false;
    }

    private boolean isSimpleType(Class<?> type) {
        return type == String.class ||
            type == int.class || type == Integer.class ||
            type == long.class || type == Long.class ||
            type == boolean.class || type == Boolean.class ||
            type == double.class || type == Double.class ||
            type == float.class || type == Float.class ||
            type == short.class || type == Short.class ||
            type == byte.class || type == Byte.class ||
            type == char.class || type == Character.class;
    }

    @SuppressWarnings("unchecked")
    private Object parseEnum(Class<?> type, String value) {
        return Enum.valueOf((Class<? extends Enum>) type, value);
    }

    private Object convert(Object value, Class<?> type) {
        if (value == null)
            return null;

        // Already the correct type
        if (type.isInstance(value))
            return value;

        // Primitive wrappers
        if (value instanceof Number number) {
            if (type == int.class || type == Integer.class)
                return number.intValue();
            if (type == long.class || type == Long.class)
                return number.longValue();
            if (type == double.class || type == Double.class)
                return number.doubleValue();
            if (type == float.class || type == Float.class)
                return number.floatValue();
            if (type == short.class || type == Short.class)
                return number.shortValue();
            if (type == byte.class || type == Byte.class)
                return number.byteValue();
        }

        if (type.isEnum() && value instanceof String s) {
            return parseEnum(type, s);
        }

        if (value instanceof Boolean b &&
            (type == boolean.class || type == Boolean.class))
            return b;

        // HTTP values will typically end up here since its all strings
        if (value instanceof String s) {
            if (type == String.class) return s;
            if (type == int.class || type == Integer.class) return Integer.valueOf(s);
            if (type == long.class || type == Long.class) return Long.valueOf(s);
            if (type == boolean.class || type == Boolean.class) return Boolean.valueOf(s);
            if (type == double.class || type == Double.class) return Double.valueOf(s);
            if (type == float.class || type == Float.class) return Float.valueOf(s);

            return gson.fromJson(s, type);
        }

        // Complex objects
        return gson.fromJson(gson.toJsonTree(value), type);
    }
}