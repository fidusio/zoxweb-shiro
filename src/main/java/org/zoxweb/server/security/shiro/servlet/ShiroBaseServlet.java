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
package org.zoxweb.server.security.shiro.servlet;

import java.io.IOException;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.http.HTTPRequestAttributes;
import org.zoxweb.server.http.servlet.HTTPServletUtil;
import org.zoxweb.server.security.shiro.authc.JWTAuthenticationToken;
import org.zoxweb.shared.api.APIError;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.JWTToken;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public abstract class ShiroBaseServlet
    extends HttpServlet
{

    public static final APIError DEFAULT_API_ERROR = new APIError(new AccessException("Access denied.", null, true));
    private static final transient Logger log = Logger.getLogger(ShiroBaseServlet.class.getName());

    public ShiroBaseServlet()
    {
        super();
    }

    protected abstract boolean isSecurityCheckRequired(HTTPMethod httpMethod, HttpServletRequest req);

    /**
     * Default patch support
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    protected void doPatch(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException
    {
        String protocol = req.getProtocol();
        String msg = "PATCH method not implemented.";

        if (protocol.endsWith("1.1"))
        {
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, msg);
        }
        else
        {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, msg);
        }
    }

    protected boolean isAutoLogoutEnabled()
    {
        return false;
    }

    /**
     * If the security check is required and the request or session is not authentication return false
     * and respond with HTTPStatusCode.UNAUTHORIZED
     *
     * @param req
     * @param res
     * @return true or false
     * @throws ServletException
     * @throws IOException
     */
    protected boolean passSecurityCheckPoint(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException
    {
        if (isSecurityCheckRequired((HTTPMethod) SharedUtil.lookupEnum(HTTPMethod.values(), req.getMethod()), req))
        {
            Subject subject = SecurityUtils.getSubject();

            if (subject == null || !subject.isAuthenticated())
            {
                log.info("security check required and user not authenticated");
                // check authentication token first
                // and try to login
                // 2 modes are supported BasicAuthenticatio and JWT
                
                HTTPRequestAttributes hra = (HTTPRequestAttributes) req.getAttribute(HTTPRequestAttributes.HRA);
                JWTToken jwtToken = hra.getJWTToken();
                if(jwtToken != null)
                {
    	    	
                	try
                	{
                		JWTAuthenticationToken authToken = new JWTAuthenticationToken(jwtToken);
                		subject = SecurityUtils.getSubject();
                		subject.login(authToken);
                		log.info("Implicit login activated");
                		return true;
                	}
                	catch(Exception e)
                	{
                		
                	}
                }

                
                HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.UNAUTHORIZED, DEFAULT_API_ERROR);
                return false;
            }
        }

        return true;
    }

    protected void postService(HttpServletRequest req, HttpServletResponse res)
    {
        if (isAutoLogoutEnabled())
        {
            Subject subject = SecurityUtils.getSubject();

            if (subject != null)
            {
                subject.logout();
                log.info("AutoLogout invoked");
            }
        }
    }

    @Override
    public void service(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException
    {
        long delta = System.nanoTime();

        try
        {
            if (passSecurityCheckPoint(req, res))
            {
                switch (req.getMethod().toUpperCase())
                {
                    case "PATCH":
                        doPatch(req, res);
                        break;
                    default:
                        super.service(req, res);
                }

                postService(req, res);
            }
        }
        finally
        {
            delta = System.nanoTime() - delta;
            log.info(getServletName() + ":" + req.getMethod() + ":PT:" + Const.TimeInMillis.nanosToString(delta));
        }
    }

}