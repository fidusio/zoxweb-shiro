package org.zoxweb.server.security.shiro;





import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.zoxweb.server.security.shiro.authz.ManualAuthorizationCheck;
//import org.zoxweb.server.security.shiro.authz.PermissionsProp;
import org.zoxweb.shared.annotation.DataProperties;

public class ShiroResourceProp<T>
{
	public final T resource;
	
	public final boolean isAuthcRequired;
	public final RequiresRoles roles;
	public final RequiresPermissions permissions;
	public final ManualAuthorizationCheck manualAuthorizationCheck;
	public final DataProperties dataProperties;
	
	
	public ShiroResourceProp(T resource, boolean authc, RequiresRoles roles, RequiresPermissions permissions, ManualAuthorizationCheck mac,DataProperties dp)
	{
		this.resource = resource;
		this.isAuthcRequired = authc;
		this.roles = roles;
		this.permissions = permissions;
		this.dataProperties = dp; 
		this.manualAuthorizationCheck = mac;
	}
	
	

}
