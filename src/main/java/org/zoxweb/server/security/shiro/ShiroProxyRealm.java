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

import java.util.HashMap;
import java.util.HashSet;
import java.util.logging.Logger;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.security.shiro.authc.DomainAuthenticationInfo;
import org.zoxweb.server.security.shiro.authc.DomainUsernamePasswordToken;
import org.zoxweb.shared.security.shiro.LoginStatusDAO;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVPair;
import org.zoxweb.shared.util.SharedUtil;

public class ShiroProxyRealm extends AuthorizingRealm
{
	private static final transient Logger log = Logger.getLogger(Const.LOGGER_NAME);

	private boolean permissionsLookupEnabled = false;
	private String proxyURL;
	private HashMap <String, LoginStatusDAO> loginMap = new HashMap<String, LoginStatusDAO>();

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
    {
		String username = (String) getAvailablePrincipal(principals);
	    String domain   = ((DomainPrincipalCollection) principals).getDomainID();
	    
	    String domainUser = SharedUtil.toCanonicalID(':', domain, username);
	    
	    LoginStatusDAO lsDAO = loginMap.get(domainUser);

		HashSet<String> roles = new HashSet<String>();

		for (NVPair nvp: lsDAO.getUserRoles()) {
			roles.add(nvp.getValue());
		}

		SimpleAuthorizationInfo ret = new SimpleAuthorizationInfo( roles);
		
		if(isPermissionsLookupEnabled()) {
			HashSet<String> permissions = new HashSet<String>();

			for (NVPair nvp: lsDAO.getUserPermissions()) {
				permissions.add( nvp.getValue());
			}

			ret.setStringPermissions(permissions);
		}

        return ret;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) 
        throws AuthenticationException
    {

		String domainID = null;
		String applicationID = null;
		String userID = null;
		
		if (proxyURL != null && token instanceof DomainUsernamePasswordToken)
		{
			domainID = ((DomainUsernamePasswordToken)token).getDomainID();
			applicationID = ((DomainUsernamePasswordToken)token).getAppID();
			userID = ((DomainUsernamePasswordToken)token).getUserID();
			
			
			try
            {
				DomainAuthenticationInfo ret = null;
				String domainUser = SharedUtil.toCanonicalID(':', domainID, token.getPrincipal());
				LoginStatusDAO lsDAO = loginMap.get(domainUser);
				//if ( lsDAO != null)
				{
					String password = new String( (char[])token.getCredentials());
					lsDAO = ShiroProxyAuthentication.login(proxyURL, true, domainID, applicationID, null, (String)token.getPrincipal(), password);
					loginMap.put(domainUser, lsDAO);
					log.info("Credential info found for " + domainUser);
				}
				
				ret = new DomainAuthenticationInfo(token.getPrincipal(), userID, token.getCredentials(), getName(), domainID, applicationID, null);
				//log.info("Credential info found for " + domainUser);
				return ret;
				
			}
			catch (Exception e)
            {
				e.printStackTrace();
				throw new AuthenticationException(e.getMessage());
			}
		}
		
		throw new AuthenticationException("Invalid token");


//		DomainAuthenticationInfo ret = new DomainAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName() , domainID, applicationID);
//		log.info( "" + token.getPrincipal() );
//		if ( !"mario".equals(token.getPrincipal()))
//			throw new AuthenticationException("Invalid token");
//		
//		return ret;
	}

	public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled)
    {
        this.permissionsLookupEnabled = permissionsLookupEnabled;
    }

	public boolean isPermissionsLookupEnabled()
    {
		return permissionsLookupEnabled;
	}

	public String getProxyURL()
    {
		return proxyURL;
	}

	public void setProxyURL(String proxyURL)
    {
		this.proxyURL = proxyURL;
	}

}