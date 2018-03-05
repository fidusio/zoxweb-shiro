package org.zoxweb.server.security.shiro.authz;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE_PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
/**
 * The permission properties are extra parameters that will allow an aop system to validate permissions
 * @author javaconsigliere
 *
 */


@Documented
@Retention(RUNTIME)
@Target({ METHOD, TYPE_PARAMETER })
public @interface PermissionsProp 
{
	/**
	 * If true the permission validation is done automatically by the aop
	 * @return
	 */
	boolean autoValidation() default true;
}
