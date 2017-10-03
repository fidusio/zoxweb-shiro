package org.zoxweb.shared.util;

import java.util.List;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.security.shiro.ZWEhCacheManager;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.data.ConfigDAO;

public class ConfigDAOTest 
{
	public static void main(String ...args)
	{
		try
		{
			ConfigDAO cd = new ConfigDAO();
			cd.setName("SimpleTest-1");
			cd.setBeanClassName(ZWEhCacheManager.class);
		
			
			String json = GSONUtil.toJSON(cd, true, false, true, null);
			cd.setName("SimpleTest-2");
			json += GSONUtil.toJSON(cd, true, false, true, null);
			System.out.println(json);
			
			
			List<ConfigDAO> results = GSONUtil.fromJSONs(json,null, ConfigDAO.class);
			System.out.println(results);
			
			
			if (args.length > 0)
			{
				json = IOUtil.inputStreamToString(args[0]);
				System.out.println(json);
				results = GSONUtil.fromJSONs(json,null, ConfigDAO.class);
				System.out.println("Object: " + results);
			}
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
}
