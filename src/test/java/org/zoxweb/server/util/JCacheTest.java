package org.zoxweb.server.util;

import java.util.concurrent.TimeUnit;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;

import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.Duration;


import javax.cache.spi.CachingProvider;

import org.zoxweb.server.security.shiro.cache.ShiroJCache;
import org.zoxweb.server.util.cache.JCacheExpiryPolicy;

public class JCacheTest {
	

	
	public static class Toto
	{
		private String str;
		public Toto(String str)
		{
			this.str = str;
		}
		
		public String toString() {return str;}
	}
	
	
	
	public static void main(String ...args)
	{
		long delta = System.currentTimeMillis();
		
		MutableConfiguration<String, Toto> configuration = new MutableConfiguration<String, Toto>();
		configuration.setTypes(String.class, Toto.class)
		.setExpiryPolicyFactory(JCacheExpiryPolicy.factoryOf(Duration.ETERNAL, new Duration(TimeUnit.MILLISECONDS, 500)))
		.setStoreByValue(false);
		
		
		
		CachingProvider provider = Caching.getCachingProvider();
		CacheManager cm = provider.getCacheManager();
		Cache<String, Toto> cache = cm.createCache("test-string", configuration);
		
		ShiroJCache<String, Toto> sjc = new ShiroJCache<>(cache);
		System.out.println("Provider:" + provider);
		System.out.println("Provider:" + cm);
		System.out.println("Provider:" + cache);
		System.out.println(sjc.size());
		Toto toto = new Toto("nael");
		
		sjc.put("marwan", toto);
		System.out.println(sjc.size());
		System.out.println("marwan:"+sjc.get("marwan"));
		System.out.println(""+sjc.get("toto"));
		System.out.println(sjc.values());
		System.out.println(sjc.keys());
		System.out.println("are equals " + (toto.equals(sjc.get("marwan"))));
		//sjc.put("marwan", new Toto("Imad"));	
		System.out.println(sjc.size());
		for(int i = 0; i < 10; i++)
		{
			sjc.put("key-" +i, new Toto("toto-"+0));
		}
		System.out.println("marwan:"+sjc.get("marwan"));
		System.out.println(sjc.size());
		try {
			Thread.sleep(5000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("marwan:"+sjc.get("marwan"));
		System.out.println(sjc.values());
		System.out.println(sjc.keys());
		
		System.out.println(sjc.size());
		System.out.println("delta :" + (System.currentTimeMillis() - delta));
		
		
		
	}

}
