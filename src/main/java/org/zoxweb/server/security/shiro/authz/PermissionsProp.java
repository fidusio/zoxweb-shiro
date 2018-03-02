package org.zoxweb.server.security.shiro.authz;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE_PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;



@Documented
@Retention(RUNTIME)
@Target({ METHOD, TYPE_PARAMETER })
public @interface PermissionsProp 
{
	// if true the permission validation is done automatically by the aop
	boolean implicitValidation() default true;
}
