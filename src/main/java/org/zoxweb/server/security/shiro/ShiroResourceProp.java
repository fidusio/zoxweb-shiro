package org.zoxweb.server.security.shiro;





import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.zoxweb.shared.annotation.DataProperties;

public class ShiroResourceProp<T>
{
	public final T resource;
	
	public final boolean isAuthcRequired;
	public final RequiresRoles roles;
	public final RequiresPermissions permissions;
	public final DataProperties dataProperties;
	
	
	public ShiroResourceProp(T resource, boolean authc, RequiresRoles roles, RequiresPermissions permissions, DataProperties rp)
	{
		this.resource = resource;
		this.isAuthcRequired = authc;
		this.roles = roles;
		this.permissions = permissions;
		this.dataProperties = rp; 
	}
	
	

}
