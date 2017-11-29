package org.zoxweb.server.security.shiro.authc;

import java.util.logging.Logger;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.JWTProvider;

import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.util.SharedStringUtil;

public class JWTPasswordCredentialsMatcher implements CredentialsMatcher {
	protected static final transient Logger log = Logger.getLogger(JWTPasswordCredentialsMatcher.class.getName());
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) 
	{
		
		
		try
        {
		
			if (info.getCredentials() instanceof PasswordDAO)
			{
				if (!token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal()))
				{
					return false;
				}
			
				if (token instanceof DomainUsernamePasswordToken
	                    && ((DomainUsernamePasswordToken)token).isAutoAuthenticationEnabled())
				{
					return true;
				}
			
	
				PasswordDAO passwordDAO = (PasswordDAO) info.getCredentials();
				String password = null;
				
				if (token.getCredentials() instanceof char[])
				{
					password = new String ((char[])token.getCredentials());
				}
				else if (token.getCredentials() instanceof byte[])
				{
					password = SharedStringUtil.toString((byte[])token.getCredentials());
				}
				else if(token.getCredentials() instanceof String)
				{
					password = (String) token.getCredentials();
				}
	
				return CryptoUtil.isPasswordValid(passwordDAO, password);
			}
			else if (info.getCredentials() instanceof byte[] && token instanceof JWTAuthenticationToken)
			{
				JWTProvider.SINGLETON.decodeJWT((byte[]) info.getCredentials(), (String)token.getCredentials());
				return true;
			}
		}
		catch (Exception e)
        {
			e.printStackTrace();
		}
		
		return false;
	}

}
