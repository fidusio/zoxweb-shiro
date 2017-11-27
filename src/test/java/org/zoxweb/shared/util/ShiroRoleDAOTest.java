/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.zoxweb.shared.util;

import org.zoxweb.server.security.shiro.ShiroUtil;
import org.zoxweb.shared.security.shiro.ShiroNVEntityCRUDs;
import org.zoxweb.shared.security.shiro.ShiroPermissionDAO;
import org.zoxweb.shared.security.shiro.ShiroRoleDAO;
import org.zoxweb.shared.util.CRUD;

public class ShiroRoleDAOTest {

	public static void main(String[] args) {
		ShiroRoleDAO role = new ShiroRoleDAO();
		role.setName("Role 1");
		role.setDomainAppID("zoxweb.com", "empty");
		
		int index = 0;
		
		ShiroPermissionDAO permission = new ShiroPermissionDAO();
		
		permission.setName("Permission 1");
		permission.setPermissionPattern("5418541");
		permission.setReferenceID("" + index++);
		permission.setDomainAppID("zoxweb.com", "empty");
		System.out.println(permission);
		role.getPermissions().add(permission);
		
		permission = new ShiroPermissionDAO();
		permission.setName("Permission 2");
		permission.setPermissionPattern("5418541");
		permission.setReferenceID("" + index++);
		System.out.println(permission);
		
		role.getPermissions().add(permission);
		
		permission = new ShiroPermissionDAO();
		permission.setName("Permission 3");
		permission.setPermissionPattern("5418541");
		permission.setReferenceID("" + index++);
		System.out.println(permission);
		
		role.getPermissions().add(permission);
		
		permission = new ShiroPermissionDAO();
		permission.setName("Permission 4");
		permission.setPermissionPattern("5418541");
		permission.setReferenceID("" + index++);
		System.out.println(permission);
		
		role.getPermissions().add(permission);		
		role.getPermissions().add(permission);
		
		System.out.println("Permissions Size: " + role.getPermissions().size());
		System.out.println("Role: " + role);
		
		ShiroNVEntityCRUDs nvCRUDs = ShiroUtil.assignCRUDs("XXXXX", CRUD.READ, CRUD.READ, CRUD.UPDATE);
		
		System.out.println(nvCRUDs.getCRUDs());
		
		for (CRUD crud : CRUD.values()) {
			System.out.println(crud + " permission: " + nvCRUDs.isPermitted(crud));
		}
	}

}
