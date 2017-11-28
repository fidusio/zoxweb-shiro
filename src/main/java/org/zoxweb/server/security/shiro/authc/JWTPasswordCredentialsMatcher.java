package org.zoxweb.server.security.shiro.authc;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.JWTProvider;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.security.JWTDAO;
import org.zoxweb.shared.util.SharedStringUtil;

public class JWTPasswordCredentialsMatcher implements CredentialsMatcher {

	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) 
	{
		if (!token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal()))
		{
			return false;
		}
		
		try
        {
			if (token instanceof DomainUsernamePasswordToken
                    && ((DomainUsernamePasswordToken)token).isAutoAuthenticationEnabled())
			{
				return true;
			}
			
			if (info.getCredentials() instanceof PasswordDAO)
			{
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
			else if (info.getCredentials() instanceof JWTDAO)
			{
				JWTDAO jwtDAO = (JWTDAO) info.getCredentials();
				JWTProvider.SINGLETON.decodeJWT(jwtDAO.getSecret(), jwtDAO.getToken());
			}
		}
		catch (Exception e)
        {
			e.printStackTrace();
		}
		
		return false;
	}

}
