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
package org.zoxweb.server.security.shiro;

import java.util.ArrayList;
import java.util.Set;
import java.util.logging.Logger;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.security.shiro.authc.DomainAuthenticationInfo;
import org.zoxweb.server.security.shiro.authc.DomainPrincipalCollection;
import org.zoxweb.server.security.shiro.authc.DomainUsernamePasswordToken;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.shiro.ShiroAssociationDAO;
import org.zoxweb.shared.security.shiro.ShiroAssociationType;
import org.zoxweb.shared.security.shiro.ShiroCollectionAssociationDAO;
import org.zoxweb.shared.security.shiro.ShiroDAO;
import org.zoxweb.shared.security.shiro.ShiroPermissionDAO;
import org.zoxweb.shared.security.shiro.ShiroRealmDAOManager;
import org.zoxweb.shared.security.shiro.ShiroRoleDAO;
import org.zoxweb.shared.security.shiro.ShiroRoleGroupDAO;
import org.zoxweb.shared.security.shiro.ShiroRulesManager;
import org.zoxweb.shared.security.shiro.ShiroSubjectDAO;
import org.zoxweb.shared.util.Const;

public abstract class ShiroBaseRealm
    extends AuthorizingRealm
    implements ShiroRulesManager, ShiroRealmDAOManager
{

	private static final transient Logger log = Logger.getLogger(Const.LOGGER_NAME);

	protected boolean permissionsLookupEnabled = false;
	

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
    {
       //null usernames are invalid
       if (principals == null)
       {
           throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
       }
       
       log.info("PrincipalCollection class:" + principals.getClass());

       if (principals instanceof DomainPrincipalCollection)
       {
	        String userID = (String) getAvailablePrincipal(principals);
	        String domainID   = ((DomainPrincipalCollection) principals).getDomainID();
	        Set<String> roleNames = getUserRoles(domainID, userID);
	        Set<String> permissions = null;
	         
	        if (isPermissionsLookupEnabled())
	        {
	        	permissions = getUserPermissions(domainID, userID, roleNames);
	        }

	        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
	        info.setStringPermissions(permissions);

	        return info;
       }

       throw new AuthorizationException("Not a domain info");
	}

	/**
	 * @see org.apache.shiro.realm.AuthenticatingRealm#doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
        throws AuthenticationException
    {
		
		if (token instanceof DomainUsernamePasswordToken)
		{
			log.info( "Domain based authentication");
			DomainUsernamePasswordToken upToken = (DomainUsernamePasswordToken) token;
	        String userName = upToken.getUsername();
	        String domainID = upToken.getDomainID();
	        String applicationID = upToken.getAppID();
	        String userID = upToken.getUserID();
	        log.info( domainID +":"+userName);
	        // Null username is invalid
	        if (userName == null)
	        {
	            throw new AccountException("Null usernames are not allowed by this realm.");
	        }

	        PasswordDAO password = getUserPassword(domainID, userName);

	         if (password == null)
	         {
	        	throw new UnknownAccountException("No account found for user [" + userID + "]");
	        }

	        return new DomainAuthenticationInfo(userName, userID, password, getName(), domainID, applicationID);
	    }	
		 throw new AuthenticationException("Not a domain info");
	}
	
	protected abstract PasswordDAO getUserPassword(String domainID, String userID);
	protected abstract Set<String> getUserRoles(String domainID, String userID);
	protected abstract Set<String> getUserPermissions(String domainID, String userID, Set<String> roleNames);

	public boolean isPermissionsLookupEnabled()
	{
		return permissionsLookupEnabled;
	}

	public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled)
    {
		this.permissionsLookupEnabled = permissionsLookupEnabled;
	}
	
	

	public ShiroSubjectDAO addSubject(ShiroSubjectDAO subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public ShiroSubjectDAO deleteSubject(ShiroSubjectDAO subject, boolean withRoles)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public ShiroSubjectDAO updateSubject(ShiroSubjectDAO subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleDAO addRole(ShiroRoleDAO role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleDAO deleteRole(ShiroRoleDAO role, boolean withPermissions)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleDAO updateRole(ShiroRoleDAO role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleGroupDAO addRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ShiroRoleGroupDAO deleteRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleGroupDAO updateRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroPermissionDAO addPermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroPermissionDAO deletePermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroPermissionDAO updatePermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroSubjectDAO> getAllShiroSubjects() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroRoleDAO> getAllShiroRoles() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroRoleGroupDAO> getAllShiroRoleGroups() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroPermissionDAO> getAllShiroPermissions() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroSubjectDAO lookupSubject(String userName)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroDAO shiroDao, ShiroAssociationType sat)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroAssociationDAO addShiroAssociationDAO(ShiroAssociationDAO association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroAssociationDAO removeShiroAssociationDAO(ShiroAssociationDAO association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

}