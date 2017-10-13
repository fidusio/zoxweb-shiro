package org.zoxweb.server.util;

import java.io.File;
import java.util.Collection;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.util.Factory;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.data.StatCounter;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

public class ShiroTest 
{
	public static void main(String ...args)
	{
		try
		{
			int index = 0;
			ClassLoader classLoader = ShiroTest.class.getClassLoader();
			String filename = args[index++];
			File file = new File(classLoader.getResource(filename).getFile());
			System.out.println(IOUtil.inputStreamToString(file));
	
			//1.
		    Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:" + filename);

		    //2.
		    SecurityManager securityManager = factory.getInstance();

		    //3.
		    SecurityUtils.setSecurityManager(securityManager);
		    Subject currentUser = SecurityUtils.getSubject();
		    Session session = currentUser.getSession();
		    session.setAttribute( "someKey", "aValue" );

		    String subjectID = args[index++];
		    String password  = args[index++];
		    if ( !currentUser.isAuthenticated() ) {
		        //collect user principals and credentials in a gui specific manner
		        //such as username/password html form, X509 certificate, OpenID, etc.
		        //We'll use the username/password example here since it is the most common.
		        UsernamePasswordToken token = new UsernamePasswordToken(subjectID, password);

		        //this is all you have to do to support 'remember me' (no config - built in!):
		        token.setRememberMe(true);

		        currentUser.login(token);
		    }
		    
		    
		    Collection<Realm> realms =  ((RealmSecurityManager)SecurityUtils.getSecurityManager()).getRealms();
		    System.out.println(realms);
		    
		    String permissions[]=
		    	{
		    		"read:batata",
		    		"write:batata", 
		    		"update:batata",
		    		"batata:update",
		    		"batata:update:all",
		    		"file:read:f1",
		    		"file:write:f2"
		    	};
		    
		    StatCounter sc = new StatCounter();
		    for(int i=0 ; i < 1; i++)
		    for (String permission : permissions)
		    {
		    		//currentUser.isPermitted(permission);
		    		
		    		System.out.println(permission + " stat:" + currentUser.isPermitted(permission));
		    }
		    System.out.println(sc.deltaSinceCreation());
		    
		    
		    
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		
		System.exit(0);
	}
}

