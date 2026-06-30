package com.lauriewired.endpoints;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface Param {

    boolean nullable() default false;
    ParamLocation location() default ParamLocation.Auto;
    String name();
    String description() default "";
}