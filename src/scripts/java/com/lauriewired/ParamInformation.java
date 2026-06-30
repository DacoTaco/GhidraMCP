package com.lauriewired;

record ParamInformation(
    String name,
    String description,
    Class<?> type,
    boolean nullable,
    boolean body
) {}