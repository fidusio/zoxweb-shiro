package org.zoxweb.server.security.shiro.cache;

import org.apache.shiro.ShiroException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;

public class ShiroJCacheManager 
	implements CacheManager, Initializable, Destroyable
{

	@Override
	public void destroy()
			throws Exception
		
	{
		// TODO Auto-generated method stub
		
	}

	@Override
	public void init()
			throws ShiroException
	{
		// TODO Auto-generated method stub
		
	}

	@Override
	public <K, V> Cache<K, V> getCache(String name)
			throws CacheException
	{
		// TODO Auto-generated method stub
		return null;
	}

}
