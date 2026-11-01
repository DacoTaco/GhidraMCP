package com.lauriewired.util;

import java.util.List;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;

/**
 * Helpers for namespaces and moving symbols between namespaces.
 */
public final class NamespacesUtils {

    private NamespacesUtils() {
    }

    public static boolean IsGlobalNamespace(String namespace) {
        return namespace == null || namespace.isBlank() || namespace.trim().equalsIgnoreCase("global");
    }

    /**
     * Finds an existing namespace by its full path (e.g. "A::B").
     *
     * @return the namespace, or null when it does not exist
     * @throws IllegalArgumentException when the path matches more than one
     * namespace
     */
    public static Namespace FindNamespace(Program program, String namespace) {
        if (IsGlobalNamespace(namespace)) {
            return program.getGlobalNamespace();
        }

        List<Namespace> matches = NamespaceUtils.getNamespaceByPath(program, null, namespace.trim());
        if (matches == null || matches.isEmpty()) {
            return null;
        }

        if (matches.size() > 1) {
            throw new IllegalArgumentException("Namespace '" + namespace + "' is ambiguous, " + matches.size() + " namespaces match");
        }
        return matches.getFirst();
    }

    /**
     * Finds or creates the namespace path (e.g. "A::B"). Must run inside a
     * transaction.
     *
     * @param asClass when true the last namespace of the path becomes a class:
     * it is created as a class, or an existing namespace is converted to one
     */
    public static Namespace GetOrCreateNamespace(Program program, String namespacePath, boolean asClass) throws Exception {
        if (IsGlobalNamespace(namespacePath)) {
            if (asClass) {
                throw new IllegalArgumentException("The global namespace can't be a class");
            }
            return program.getGlobalNamespace();
        }

        Namespace namespace = FindNamespace(program, namespacePath);
        if (namespace != null) {
            if (asClass && !(namespace instanceof GhidraClass)) {
                namespace = NamespaceUtils.convertNamespaceToClass(namespace);
            }
            return namespace;
        }

        if (!asClass) {
            return NamespaceUtils.createNamespaceHierarchy(namespacePath.trim(), null, program, SourceType.USER_DEFINED);
        }

        SymbolPath path = new SymbolPath(namespacePath.trim());
        Namespace parent = path.getParentPath() == null
                ? program.getGlobalNamespace()
                : NamespaceUtils.createNamespaceHierarchy(path.getParentPath(), null, program, SourceType.USER_DEFINED);
        return program.getSymbolTable().createClass(parent, path.getName(), SourceType.USER_DEFINED);
    }

    /**
     * Splits a name like "A::B::name" into its namespace path ("A::B") and name
     * ("name").
     *
     * @return the namespace path (null when the name has none) and the name
     */
    public static String[] SplitQualifiedName(String qualifiedName) {
        SymbolPath path = new SymbolPath(qualifiedName.trim());
        return new String[]{path.getParentPath(), path.getName()};
    }

    /**
     * Moves a function into a namespace and optionally renames it. Must run
     * inside a transaction.
     *
     * @param name the new name, or null to keep the current one. When the
     * function still has a flat name containing "::" (e.g.
     * "TCameraCtrl::setMode") only the last part is kept when moving it into a
     * non-global namespace.
     * @param asClass make the namespace a class and give the function a this
     * parameter (__thiscall)
     * @throws Exception when the function could not be moved or its calling
     * convention could not be set
     */
    public static void MoveFunction(Program program, Function function, String namespacePath, String name, boolean asClass) throws Exception {
        Namespace namespace = GetOrCreateNamespace(program, namespacePath, asClass);

        String newName = name;
        if (newName == null || newName.isBlank()) {
            newName = function.getName();
            if (!namespace.isGlobal() && newName.contains("::")) {
                newName = SplitQualifiedName(newName)[1];
            }
        }

        function.getSymbol().setNameAndNamespace(newName.trim(), namespace, SourceType.USER_DEFINED);

        if (asClass && !"__thiscall".equals(function.getCallingConventionName())) {
            function.setCallingConvention("__thiscall");
        }
    }
}
