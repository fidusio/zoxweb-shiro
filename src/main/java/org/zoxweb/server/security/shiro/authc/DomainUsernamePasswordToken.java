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
package org.zoxweb.server.security.shiro.authc;

import org.apache.shiro.authc.UsernamePasswordToken;
import org.zoxweb.shared.util.AppID;
import org.zoxweb.shared.util.SharedStringUtil;

@SuppressWarnings("serial")
public class DomainUsernamePasswordToken
    extends UsernamePasswordToken
    implements AppID<String>
{

	private String domain_id;
	private String app_id;
	private String user_id;
	private boolean autoAuthenticationEnabled = false;

	public DomainUsernamePasswordToken()
    {
		
	}
	
	public DomainUsernamePasswordToken(final String usnernanme, final String password,
            final boolean rememberMe, final String host, final String domainID)
    {
		this(usnernanme, password, rememberMe, host, domainID, null);
	}
	
	public DomainUsernamePasswordToken(final String usnernanme, final String password,
            final boolean rememberMe, final String host, final String domainID, String applicationID)
    {
		super(SharedStringUtil.toLowerCase(usnernanme), password, rememberMe, host);
		setDomainID(domainID);
		setAppID(applicationID);
		//setUserID(realmID);
	}

	public String getDomainID()
    {
		return domain_id;
	}

	public void setDomainID(String domainID)
    {
		this.domain_id = SharedStringUtil.trimOrEmpty(SharedStringUtil.toLowerCase(domainID));
	}
	
	public String getAppID()
    {
		return app_id;
	}

	public void setAppID(String applicationID)
    {
		this.app_id = SharedStringUtil.trimOrEmpty(SharedStringUtil.toLowerCase(applicationID));
	}
	
	public String getUserID()
    {
		return user_id;
	}
	
	public void setUserID(String userID)
    {
		user_id = userID;
	}
	
	
	
	public boolean isAutoAuthenticationEnabled()
    {
		return autoAuthenticationEnabled;
	}

	public void setAutoAuthenticationEnabled(boolean autoAuthenticationEnabled)
    {
		this.autoAuthenticationEnabled = autoAuthenticationEnabled;
	}

	@Override
	public String getSubjectID() {
		// TODO Auto-generated method stub
		return getUsername();
	}

	@Override
	public void setSubjectID(String subjectID) {
		// TODO Auto-generated method stub
		setUsername(subjectID);
	}

	@Override
	@Deprecated
	public String getAppGID()
		throws UnsupportedOperationException
	{
		throw new UnsupportedOperationException();
		// TODO Auto-generated method stub
	}

	@Override
	@Deprecated
	public void setAppGID(String appGID)
		throws UnsupportedOperationException
	{
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException();
	}

}