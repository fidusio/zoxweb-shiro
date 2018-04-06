package org.zoxweb.shared.util;

import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.security.shiro.ShiroPermissionDAO;

public class RolesAndPemissions {

	public static void main(String[] args) 
	{
		try
		{
			ShiroPermissionDAO permision = SecurityModel.Permission.ADD_RESOURCE.toPermission("test.com", "batata");
			System.out.println(GSONUtil.toJSON(permision, true));
		
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}

		

	}

}
