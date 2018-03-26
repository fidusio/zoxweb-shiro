package org.zoxweb.server.security.shiro;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.zoxweb.server.security.shiro.authz.ManualPermissionsCheck;
//import org.zoxweb.server.security.shiro.authz.PermissionsProp;
import org.zoxweb.shared.annotation.DataProperties;

public class ShiroResourcePropScanner
{
	private ShiroResourcePropScanner()
	{	
	}
	
	public static ShiroResourcePropContainer scan(Class<?> clazz)
	{
		ShiroResourcePropContainer ret = null;
		{
			boolean  authc = false;
			RequiresPermissions permissionAnnot = null;
			RequiresRoles rolesAnnot = null;
			
			for (Annotation a : clazz.getAnnotations())
			{
				
				if (a.annotationType() == RequiresAuthentication.class)
				{
					authc = true;
					
				}
				else if (a.annotationType() == RequiresPermissions.class)
				{
					permissionAnnot = (RequiresPermissions) a;
				}
				else if (a.annotationType() == RequiresRoles.class)
				{
					rolesAnnot = (RequiresRoles) a;
				}	
			}
			
			ret = new ShiroResourcePropContainer(clazz, authc, rolesAnnot, permissionAnnot);
		}
		
		for(Method m : clazz.getMethods())
		{
			ShiroResourceProp<Method> srp = null;
			
			boolean  authc = false;
			RequiresPermissions permissionAnnot = null;
			RequiresRoles rolesAnnot = null;
			ManualPermissionsCheck permissionsProp = null;
			DataProperties dataProp = null;
			
			
			for (Annotation a : m.getAnnotations())
			{
				
				if (a.annotationType() == RequiresAuthentication.class)
				{
					authc = true;
				}
				else if (a.annotationType() == RequiresPermissions.class)
				{
					permissionAnnot = (RequiresPermissions) a;
				}
				else if (a.annotationType() == RequiresRoles.class)
				{
					rolesAnnot = (RequiresRoles) a;
				}
				else if (a.annotationType() == ManualPermissionsCheck.class)
				{
					permissionsProp = (ManualPermissionsCheck) a;
				}
				else if (a.annotationType() == DataProperties.class)
				{
					dataProp = (DataProperties) a;
				}
			}
			
			if (authc || permissionAnnot != null || rolesAnnot != null || dataProp != null)
				srp = new ShiroResourceProp<Method>(m, authc, rolesAnnot, permissionAnnot, permissionsProp, dataProp);
			
			ret.add(srp);
		}
		
		
		
		return ret;
	}
}
