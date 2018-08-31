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
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.http.HTTPRequestAttributes;
import org.zoxweb.server.http.servlet.HTTPServletUtil;
import org.zoxweb.server.security.shiro.ShiroResourceProp;
import org.zoxweb.server.security.shiro.ShiroResourcePropContainer;
import org.zoxweb.server.security.shiro.ShiroResourcePropScanner;
import org.zoxweb.server.security.shiro.ShiroUtil;
import org.zoxweb.server.security.shiro.authc.JWTAuthenticationToken;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.cache.JWTTokenCache;
import org.zoxweb.shared.annotation.DataProperties;
import org.zoxweb.shared.api.APIError;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.data.ApplicationConfigDAO;
import org.zoxweb.shared.data.ApplicationConfigDAO.ApplicationDefaultParam;
import org.zoxweb.shared.http.HTTPAuthentication;
import org.zoxweb.shared.http.HTTPAuthenticationBasic;
import org.zoxweb.shared.http.HTTPHeaderName;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.JWTToken;
import org.zoxweb.shared.security.SecurityConsts.AuthType;
import org.zoxweb.shared.util.AppIDURI;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.Const.Bool;
import org.zoxweb.shared.util.ExceptionReason;
import org.zoxweb.shared.util.ExceptionReason.Reason;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;
import org.zoxweb.shared.util.SharedBase64.Base64Type;
import org.zoxweb.shared.util.SharedStringUtil;

@SuppressWarnings("serial")
public abstract class ShiroBaseServlet
    extends HttpServlet
{

    public static final APIError DEFAULT_API_ERROR = new APIError(new AccessException("Access denied.", null, true));
    private static final transient Logger log = Logger.getLogger(ShiroBaseServlet.class.getName());
    
    
    //public static final String SECURITY_CHECK = "SECURITY_CHECK";
    public static final String AUTO_LOGOUT = "AUTO_LOGOUT";
    public static final String APP_ID_IN_PATH = "APP_ID_IN_PATH";
    protected boolean isSecurityCheckRequired = false;
    protected boolean isAutoLogout = false;
    protected boolean isAppIDInPath = false;
    private static AtomicLong serviceCounter = new AtomicLong();
    //protected  Map<HTTPMethod, DataProperties> httpResourceAccessProps = new HashMap<HTTPMethod, DataProperties>();
    protected ShiroResourcePropContainer resourceProps = null;
    
    public void init(ServletConfig config)
            throws ServletException
    {
    	super.init(config);
    	
 
    	isAutoLogout = config.getInitParameter(AUTO_LOGOUT) != null ? Bool.lookupValue(config.getInitParameter(AUTO_LOGOUT)) : false;
    	isAppIDInPath = config.getInitParameter(APP_ID_IN_PATH) != null ? Bool.lookupValue(config.getInitParameter(APP_ID_IN_PATH)) : false;
    	log.info("isSecurityCheckRequired:"+isSecurityCheckRequired+",isAutoLogout:"+isAutoLogoutEnabled());
    	
    	resourceProps = ShiroResourcePropScanner.scan(getClass());
    	
    	
    	for(ShiroResourceProp<?> srp : resourceProps.getAllResources())
    	{
    		@SuppressWarnings("unchecked")
			ShiroResourceProp<Method> srpm = (ShiroResourceProp<Method>) srp;
    		
    		HTTPMethod hm = HTTPMethod.lookup(srpm.resource.getName());
    		if (hm != null)
    		{
    			resourceProps.map(hm, srpm);
    		}
    	}
    	isSecurityCheckRequired = resourceProps.isAuthcRequired;
    	
    	
    }
    
    

    /**
     * This method is kept to backward compatibility
     * @param httpMethod
     * @param req
     * @return
     */
    protected boolean isSecurityCheckRequired(HTTPMethod httpMethod, HttpServletRequest req)
    {
    	@SuppressWarnings("unchecked")
		ShiroResourceProp<Method> srpm = (ShiroResourceProp<Method>) resourceProps.lookupByResourceMap(httpMethod);
    	
    	if (srpm != null && srpm.isAuthcRequired)
    	{
    		return true;
    	}
    		
    	return isSecurityCheckRequired;
    }

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

    /**
     * If true the subject will be logged out and session invalidated
     * @return
     */
    protected boolean isAutoLogoutEnabled()
    {
        return isAutoLogout;
    }
    
    protected boolean isAppIDPathRequired(HttpServletRequest req)
    {
    	return isAppIDInPath;
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
    protected boolean authenticationCheckPoint(HTTPMethod httpMethod, HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException
    {
        if (isSecurityCheckRequired(httpMethod, req))
        {
        	
        	Exception exp = null;
            Subject subject = SecurityUtils.getSubject();
            AuthType reqAuth = AuthType.NONE;

            if (subject == null || !subject.isAuthenticated())
            {
            	
                //log.info("security check required and user not authenticated");
                // check authentication token first
                // and try to login
                // 2 modes are supported BasicAuthenticatio and JWT
                
                HTTPRequestAttributes hra = (HTTPRequestAttributes) req.getAttribute(HTTPRequestAttributes.HRA);
                JWTToken jwtToken = hra.getJWTToken();
                if(jwtToken != null)
                {
    	    	
                	try
                	{
                		
                		JWTTokenCache jwtCache = ResourceManager.SINGLETON.lookup(ResourceManager.Resource.JWT_CACHE);
                		if(jwtCache != null)
                		{
                			// if the cache is available check the cache
                			jwtCache.map(jwtToken);
                		}
                		JWTAuthenticationToken authToken = new JWTAuthenticationToken(jwtToken);
                		subject = SecurityUtils.getSubject();
                		subject.login(authToken);
                		//log.info("Implicit login activated");
                		//long ts = System.currentTimeMillis();
                		if (jwtToken.getJWT().getPayload().getIssuedAt() != 0)
                		{
                			//log.info("JWT IAT:" + jwtToken.getJWT().getPayload().getIssuedAt() + " time difference between s/c " + (ts - jwtToken.getJWT().getPayload().getIssuedAt() ));
                		}
                		return true;
                	}
                	catch(Exception e)
                	{
                		exp = e;
                		reqAuth = AuthType.BEARER;
                	}
                }
                else
                {
                	// maybe base 64 authentication
                	try
                	{
                		HTTPAuthentication httpAuth = hra.getHTTPAuthentication();
                		if (httpAuth != null && httpAuth instanceof HTTPAuthenticationBasic)
                		{
                			HTTPAuthenticationBasic basic = (HTTPAuthenticationBasic) httpAuth;
                			
                			
                			AppIDURI appIDURI = hra.getAppIDURI();
                			
                			// check in the app id is required and in present in the uri
                			if(isAppIDPathRequired(req) && appIDURI == null)
                			{
                				
                				throw new APIException();
                			}
                			
                			
                			//System.out.println(appIDURI.getAppIDDAO());
                			String domainID = appIDURI != null ? appIDURI.getAppIDDAO().getDomainID() : null;
                			String appID = appIDURI != null ? appIDURI.getAppIDDAO().getAppID() : null;
                			ShiroUtil.loginSubject(basic.getUser(), basic.getPassword(), domainID, appID, false);
                			return true;
                		}
                	}
                	catch(Exception e)
                	{
                		reqAuth = AuthType.BASIC;
                	}
                }
                
                //log.info("ReqAuth:" +reqAuth);
                //log.info(hra.getPathInfo());
                
                if (reqAuth == AuthType.NONE)  	
                {
              
                	ApplicationConfigDAO acd = ResourceManager.SINGLETON.lookup(ApplicationConfigDAO.RESOURCE_NAME);
                	String realm = "domain_access";
                	if (acd != null)
                	{
                		realm = acd.lookupValue(ApplicationDefaultParam.APPLICATION_HOST) != null ? acd.lookupValue(ApplicationDefaultParam.APPLICATION_HOST) : realm;
                	}
                	res.addHeader(HTTPHeaderName.WWW_AUTHENTICATE.getName(), "Basic realm=\"" + realm + "\", charset=\"UTF-8\"" );
                	res.setStatus(HTTPStatusCode.UNAUTHORIZED.CODE);
                }
                else
                {
                	HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.UNAUTHORIZED, exp != null ? new APIError(exp) : DEFAULT_API_ERROR);
                }
                return false;
            }
        }

        return true;
    }
    
   
	@SuppressWarnings("unchecked")
	protected boolean authorizationCheckPoint(HTTPMethod httpMethod, HttpServletRequest req, HttpServletResponse res) throws IOException
    {
    	
		ShiroResourceProp<Method> srpm = (ShiroResourceProp<Method>) resourceProps.lookupByResourceMap(httpMethod);
		
		if (srpm != null)
		{
			// check for assigned permission or roles
			if (srpm.roles != null && srpm.manualAuthorizationCheck == null)
			{
				try
				{
					ShiroUtil.checkRoles((srpm.roles.logical() == Logical.OR), SecurityUtils.getSubject(), srpm.roles.value());
				}
				catch(Exception e)
				{
					HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.UNAUTHORIZED, new APIError(e));
					return false;
				}
			}
			
			if (srpm.permissions != null && srpm.manualAuthorizationCheck == null)
			{
				try
				{
					ShiroUtil.checkPermissions((srpm.permissions.logical() == Logical.OR), SecurityUtils.getSubject(), srpm.permissions.value());
				}
				catch(Exception e)
				{
					HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.UNAUTHORIZED, new APIError(e));
					return false;
				}
			}
		}
    	return true;
    }
	
	@SuppressWarnings("unchecked")
	protected void dataDecoding(HTTPMethod httpMethod, HttpServletRequest req, HttpServletResponse res)
	{
		ShiroResourceProp<Method> srpm = (ShiroResourceProp<Method>) resourceProps.lookupByResourceMap(httpMethod);
		// check if we need to autoconvert data object
		DataProperties dct = srpm !=null ? srpm.dataProperties : null;
		if (dct != null && dct.dataAutoConvert())
		{
			HTTPRequestAttributes hra = (HTTPRequestAttributes) req.getAttribute(HTTPRequestAttributes.HRA);
			if (!SharedStringUtil.isEmpty(hra.getContent()))
			{
				Class<?> retType = dct.dataType();
				try
				{
    				if (NVEntity.class.isAssignableFrom(retType))
    				{
    					hra.setDataContent(GSONUtil.fromJSON(hra.getContent(), (Class<? extends NVEntity>) retType));
    				}
    				else if (retType.isAssignableFrom(NVGenericMap.class))
    				{
    					hra.setDataContent(GSONUtil.fromJSONGenericMap(hra.getContent(), null, Base64Type.DEFAULT));
    				}
				}
				catch(Exception e)
				{
					e.printStackTrace();
					throw new APIException("Content not matching", Reason.INCOMPLETE);
				}
			}
			else if (dct.dataRequired())
			{
				// we have an empty content check if it is allowed
				// we have missing content generate error
				throw new APIException("Content empty", Reason.INCOMPLETE);
				
			}
			
		}
	}

    protected void postService(HttpServletRequest req, HttpServletResponse res)
    {
        if (isAutoLogoutEnabled())
        {
            Subject subject = SecurityUtils.getSubject();

            if (subject != null && subject.isAuthenticated())
            {
                subject.logout();
                log.info("AutoLogout invoked:" + SecurityUtils.getSecurityManager().getClass().getName());
                
            }
        }
    }
    
	@Override
    protected void service(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException
    {
        long delta = System.nanoTime();
        serviceCounter.incrementAndGet();

        try
        {
        	
        	HTTPMethod hm = HTTPMethod.lookup(req.getMethod());
        	if (hm == null)
        	{
        		super.service(req, res);
        		return;
        	}
        	// Note always call authentication checkpoint first
        	// then authorizationCheckPoint check point
        	// because subject must be authenticated before getting authorized
            
        	try 
        	{
        		if (!(authenticationCheckPoint(hm, req, res) &&
        			  authorizationCheckPoint(hm, req, res)))
        		{
        			// check point failed error processed by the check point
        			// we should return
        			return;
        		}
        		
        		
        		// data decoding if required
        		dataDecoding(hm, req, res);
        		
        		
        		switch (req.getMethod().toUpperCase())
        		{
                	case "PATCH":
                		doPatch(req, res);
                		break;
                	default:
                		super.service(req, res);
        		}
        	}
        	catch(AccessException | APIException | NullPointerException | IllegalArgumentException e)
        	{
        		
        		if (e instanceof ExceptionReason)
        		{
        			switch(((ExceptionReason) e).getReason())
        			{
					case ACCESS_DENIED:
						HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.FORBIDDEN, new APIError(e));
						break;
					case UNAUTHORIZED:
						HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.UNAUTHORIZED, new APIError(e));
						break;
					case INCOMPLETE:
						HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.BAD_REQUEST, new APIError(e));
						break;
					case NOT_FOUND:
						HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.NOT_FOUND, new APIError(e));
						break;
        			}
        		}
        		else if(e instanceof IllegalArgumentException)
        		{
        			HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.BAD_REQUEST, e.getMessage());
        		}
        		else if(e instanceof NullPointerException)
        		{
        			HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.INTERNAL_SERVER_ERROR, e.getMessage());
        		}
        	}
//        	catch(Exception e)
//        	{
//        		e.printStackTrace();
//        	}
        }
        finally
        {
        	postService(req, res);
            delta = System.nanoTime() - delta;
            log.info(getServletName() + ":" + req.getMethod() + ":PT:" + Const.TimeInMillis.nanosToString(delta) +":TOTAL CALLS:" + serviceCounter.get());
        }
    }

}