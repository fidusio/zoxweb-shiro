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

import org.apache.shiro.subject.SimplePrincipalCollection;
import org.zoxweb.shared.util.SharedStringUtil;

@SuppressWarnings("serial")
public class DomainPrincipalCollection
    extends SimplePrincipalCollection
{

	protected String domain_id;
	protected String application_id;
	protected String user_id;

	/**
     *
	 * @param principal the login id ie email
	 * @param userID unique user domain identifier 
	 * @param realmName
	 * @param domainID
	 * @param applicationID
	 */
	public DomainPrincipalCollection(Object principal, String userID, String realmName, String domainID, String applicationID)
    {
		super(principal, realmName);
		domain_id = SharedStringUtil.toLowerCase(domainID);
		application_id = SharedStringUtil.toLowerCase(applicationID);
		user_id = userID;
    }
	
    public String getDomainID()
    {
		return domain_id;
	}
	
	public String getApplicationID()
    {
		return application_id;
	}

	/**
	 * This is a second unique identifier
	 *
	 * @return user id
	 */
	public String getUserID()
    {
		return user_id;
	}

}