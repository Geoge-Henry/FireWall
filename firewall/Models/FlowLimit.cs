using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Caching;

namespace firewall.Models
{
    //该类用于处理当个IP的访问流量限制
    public class FlowLimit
    {
        //将每次访问流量存入缓存,并判断单位时间内的流量是否超出限制额
        public bool IsOverFlow(int FlowLimitRate,int FlowBytes,string HostIp)
        {
            const int DURATION = 10;        //用于设置的单位时间,先暂定为10秒

            HttpContext context = HttpContext.Current;
            if (context.Request.Browser.Crawler) return false;  //排除浏览器爬行遍历搜索

            string FlowKey = FlowLimitRate.ToString() + HostIp; //设置缓存的key

            int FlowAllow = (Int32)(context.Cache.Get(FlowKey) ?? 0);   //设置缓存的value
            //两个问号的作用是判断??左边的对象是否为null，如果不为null则使用??左边的对象，如果为null则使用??右边的对象

            if ((FlowAllow + FlowBytes) > FlowLimitRate)    //判断总和是否超出
                return false;
            else
                FlowAllow = FlowAllow + FlowBytes;

            //存入缓存
            if (FlowAllow == FlowBytes)
            {
                context.Cache.Add(FlowKey, FlowAllow, null, DateTime.Now.AddSeconds(DURATION),
                    Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
            }
            else
            {
                context.Cache.Insert(FlowKey, FlowAllow, null, Cache.NoAbsoluteExpiration,
                    TimeSpan.FromSeconds(DURATION), CacheItemPriority.Normal, null);
            }
            return true;
        }
    }
}