using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Caching;

namespace firewall.Models
{
    //该类用于处理当个IP的访问频率限制
    public class FrequenceLimit
    {
        //将每次访问流量存入缓存,并判断单位时间内的访问次数是否超出限制额
        public bool IsOverTimesNum(int TimesNum,string HostIp)
        {
            const int DURATION = 10;          //用于设置的单位时间,先暂定为10秒
            HttpContext context = HttpContext.Current;
            if (context.Request.Browser.Crawler) return false;      //排除浏览器爬行遍历搜索

            string key = TimesNum.ToString() + HostIp;           //设置缓存的key
            
            //两个问号的作用是判断??左边的对象是否为null，如果不为null则使用??左边的对象，如果为null则使用??右边的对象
            int hit = (Int32)(context.Cache.Get(key) ?? 0);     //设置缓存的value
            string VisitKey = hit.ToString() + "@" + HostIp;    //设置key2
            bool VisitAllow = (bool)(context.Cache.Get(VisitKey) ?? true);      //设置value2
            hit++;

            if (context.Cache.Get((hit - TimesNum).ToString() + "@" + HostIp) != null)      //判断是否超出次数限制
                return false;

            //存入缓存
            if (hit == 1)
            {
                context.Cache.Add(key, hit, null, DateTime.Now.AddSeconds(DURATION), 
                    Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
                context.Cache.Add(VisitKey, VisitAllow, null, DateTime.Now.AddSeconds(DURATION),
                    Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
            }
            else
            {
                context.Cache.Insert(key, hit, null, Cache.NoAbsoluteExpiration, 
                    TimeSpan.FromSeconds(DURATION), CacheItemPriority.Normal, null);
                context.Cache.Add(VisitKey, VisitAllow, null, DateTime.Now.AddSeconds(DURATION),
                    Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
            }
            return true;
        }
    }
}