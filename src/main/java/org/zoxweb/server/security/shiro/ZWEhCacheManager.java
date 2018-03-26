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

import java.io.Closeable;
import java.util.HashSet;
import java.util.Iterator;
import java.util.logging.Logger;

import org.apache.shiro.cache.CacheManager;
//import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;
import org.zoxweb.server.security.shiro.cache.ShiroJCacheManager;
import org.zoxweb.shared.util.ResourceManager;

/**
 * @author mnael
 *
 */
public class ZWEhCacheManager
    //extends EhCacheManager
	extends ShiroJCacheManager
    implements CacheManager, Initializable, Destroyable
{
	public static final String RESOURCE_NAME = "ZW_EH_CACHE_MANAGER";
	
	private static final Logger log = Logger.getLogger(ZWEhCacheManager.class.getName());
	
	//private static final HashSet<EhCacheManager> CACHE_SET = new HashSet<>();
	
	private static final CacheObject CACHE_OBJECT = new CacheObject();
	
	
	public static class CacheObject
		implements Closeable
	{
		
		final HashSet<ShiroJCacheManager> cacheSet = new HashSet<>();
		
		CacheObject()
		{
			ResourceManager.SINGLETON.map(RESOURCE_NAME, this);
		}
		
		void add(ShiroJCacheManager eh)
		{
			synchronized(cacheSet)
			{
				cacheSet.add(eh);
			}
			
		}

		@Override
		public void close() 
		{
			// TODO Auto-generated method stub
		
			
			synchronized(cacheSet)
	        {
				log.info("Started destroy all " + cacheSet.size() + " to be destroyed.");
			
				cacheSet.iterator();
				
				Iterator<ShiroJCacheManager> it = cacheSet.iterator();

				while (it.hasNext())
	            {
					try
	                {
						ShiroJCacheManager ecm = it.next();
						ecm.destroy();
						log.info("Destroyed:" + ecm);
					}
					catch(Exception e)
	                {
						e.printStackTrace();
					}
				}

				cacheSet.clear();
				log.info("Finished destroy all left size: " + cacheSet.size());
			}
			
		}
		
		
	}
	
	
	public ZWEhCacheManager()
    {
		super();
		CACHE_OBJECT.add(this);	
		log.info("Created set size: " + CACHE_OBJECT.cacheSet.size());
	}
	
	public static void destroyAll()
    {
		CACHE_OBJECT.close();
	}

}