using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using System.Net;
using System.IO;

namespace firewall.Models
{
    public class Home                                                   //该类用于分析客户端的http请求信息的合法性
    {
        public struct HeaderStruct
        {
            public string URL{get;set;}                                 //获取URL
            public string Method { get; set; }                          //获取传输方法GET、POST等
            public string HostIp { get; set; }                          //获取请求的主机IP地址
            public string ContentType { get; set; }                     //获取请求的内容类型
            public string Port { get;set; }                             //获取请求的端口号
            public int TotalBytes { get; set; }                         //获取请求内容的字节数（流量）
            public Dictionary<string, string> Cookies { get; set; }     //获取请求中的Cookie信息
        }

        //作为请求后的返回信息的一个结构体
        public struct AnalyzeResult
        {
            public string ResultReport { get; set; }                    //请求分析后的结果
            public HeaderStruct RequestHeader { get; set; }             //请求分析后的http头信息
            public string RequestContents { get; set; }                 //请求分析后的http正文
        }

        public AnalyzeResult GetPostRequestResult(HttpRequestBase Request)         //由controller调用，获取POST请求过滤后的信息内容
        {
            HeaderStruct Header = GetHttpHeader(Request);
            return AnalyzeHttpRequest(Request,Header);
        }

        public AnalyzeResult GetGetRequestResult(HttpRequestBase Request)        //由controller调用，获取GET请求过滤后的信息内容
        {
            HeaderStruct Header = GetHttpHeader(Request);
            return AnalyzeHttpHeader(Header);
        }

        //该方法获取http请求头部信息
        public HeaderStruct GetHttpHeader(HttpRequestBase Request)     
        {
            string Url;
            if(Request.Url.ToString().Length>2048)
                Url="http://localhost/";
            Url=Request.Url.ToString();
            string Method = Request.HttpMethod.ToString();
            string HostIp = Request.UserHostAddress;
            string ContentType=Request.ContentType;
            string Port = Request.Url.Port.ToString();
            int TotalBytes = Request.TotalBytes;
            Dictionary<string, string> Cookies = new Dictionary<string, string>();
            foreach (string CookiesKey in Request.Cookies.Keys)
            {
                Cookies.Add(CookiesKey, Request.Cookies.Get(CookiesKey).Value);
            }
            HeaderStruct Header = new HeaderStruct();
            Header.URL = Url;
            Header.Method = Method;
            Header.HostIp = HostIp;
            Header.ContentType = ContentType;
            Header.Port = Port;
            Header.TotalBytes = TotalBytes;
            Header.Cookies = Cookies;
            return Header;
        }

        private AnalyzeResult AnalyzeHttpRequest(HttpRequestBase Request,HeaderStruct Header)      //该方法用于分析http请求的头部信息
        {
            //实例化http的POST请求的分析结果
            AnalyzeResult PostAnalyzeResult = new AnalyzeResult();
            //判断该请求是否有为黑名单，是否设置了访问流量限制和访问频率限制
            LimitList LimitJudge = new LimitList();
            FrequenceLimit FrequenceJudge = new FrequenceLimit();
            FlowLimit FlowJudge = new FlowLimit();
            if(!LimitJudge.IsLimitVisitor(Header.HostIp))
            {
                PostAnalyzeResult.ResultReport = "该主机已被设置为黑名单，无法访问";
                return PostAnalyzeResult;
            }

            if (LimitJudge.GetLimitVisitorTotalRate(Header.HostIp) > 0)
            {
                if (!FrequenceJudge.IsOverTimesNum(LimitJudge.GetLimitVisitorTotalRate(Header.HostIp), Header.HostIp))
                {
                    PostAnalyzeResult.ResultReport = "请求过于频繁，系统自动判定为异常请求！请稍后再试！";
                    return PostAnalyzeResult;
                }
            }
            else if (LimitJudge.GetLimitVisitorTotalRate(Header.HostIp) == 0)
            {
                PostAnalyzeResult.ResultReport = "数据库出错";
                return PostAnalyzeResult;
            }

            if (LimitJudge.GetLimitFlowTotalRate(Header.HostIp) > 0)
            {
                if (!FlowJudge.IsOverFlow(LimitJudge.GetLimitFlowTotalRate(Header.HostIp), Header.TotalBytes, Header.HostIp))
                {
                    PostAnalyzeResult.ResultReport = "请求信息量太大，系统自动判定为异常请求！请稍后再试！";
                    return PostAnalyzeResult;
                }
            }
            else if (LimitJudge.GetLimitFlowTotalRate(Header.HostIp) == 0)
            {
                PostAnalyzeResult.ResultReport = "数据库错误";
                return PostAnalyzeResult;
            }

            IPAddress CheckIPAddress = null;
            if (!IPAddress.TryParse(Header.HostIp, out CheckIPAddress))
            {
                PostAnalyzeResult.ResultReport = "请求报文的IP地址不合法！";
                return PostAnalyzeResult;
            }

            //获取请求字符串，并判断请求长度是否合法
            if (Request.ContentLength > (Int32.MaxValue) / 50)
            {
                PostAnalyzeResult.ResultReport = "请求内容太大，丢弃请求！";
                return PostAnalyzeResult;
            }

            //通过流到字符的转化，将请求内容获取到RequestContent变量
            Stream RequestStream = Request.InputStream;
            StreamReader MyStream = new StreamReader(RequestStream, Encoding.UTF8);
            string RequestContent = MyStream.ReadToEnd();

            HttpRequestFilter Filter = new HttpRequestFilter();             
            RequestContent = Filter.HTMLFilter(RequestContent);                             //过滤HTML标签
            RequestContent = Filter.SqlFilter(RequestContent);                              //过滤sql关键字
            RequestContent = Filter.SpecialCharFilter(RequestContent);                      //过滤特殊字符
            RequestContent = Filter.XSSFilter(RequestContent);                              //过滤XSS脚本

            if (RequestContent =="HTML标签过滤异常" || RequestContent =="特殊字符过滤异常" 
                || RequestContent == "SQL字符过滤异常" || RequestContent == "XSS过滤异常")
            {
                PostAnalyzeResult.ResultReport = RequestContent;
                return PostAnalyzeResult;
            }

            Header.URL = Filter.URLFilter(Header.URL);                                      //过滤URL特殊字符
            if (Header.URL == "URL字符过滤异常")
            {
                PostAnalyzeResult.ResultReport = Header.URL;
                return PostAnalyzeResult;
            }

            PostAnalyzeResult.ResultReport = "请求过滤成功";
            PostAnalyzeResult.RequestHeader = Header;
            PostAnalyzeResult.RequestContents = RequestContent;
            return PostAnalyzeResult;
        }

        private AnalyzeResult AnalyzeHttpHeader(HeaderStruct Header)
        {
            //实例化http的GET请求的分析结果
            AnalyzeResult GetMethodResult = new AnalyzeResult();
            //判断该请求是否有为黑名单，是否设置了访问流量限制和访问频率限制
            LimitList LimitJudge = new LimitList();
            FrequenceLimit FrequenceJudge = new FrequenceLimit();
            FlowLimit FlowJudge = new FlowLimit();

            GetMethodResult.RequestHeader = Header;
            GetMethodResult.RequestContents = string.Empty;

            if (!LimitJudge.IsLimitVisitor(Header.HostIp))
            {
                GetMethodResult.ResultReport = "该主机已被设置为黑名单，无法访问";
                return GetMethodResult;
            }

            if (LimitJudge.GetLimitVisitorTotalRate(Header.HostIp) > 0)
            {
                if (!FrequenceJudge.IsOverTimesNum(LimitJudge.GetLimitVisitorTotalRate(Header.HostIp), Header.HostIp))
                {
                    GetMethodResult.ResultReport = "请求过于频繁，系统自动判定为异常请求！请稍后再试！";
                    return GetMethodResult;
                }
            }
            else if (LimitJudge.GetLimitVisitorTotalRate(Header.HostIp) == 0)
            {
                GetMethodResult.ResultReport = "数据库出错";
                return GetMethodResult;
            }

            IPAddress CheckIPAddress = null;
            if (!IPAddress.TryParse(Header.HostIp, out CheckIPAddress))
            {
                GetMethodResult.ResultReport = "请求报文的IP地址不合法！";
                return GetMethodResult;
            }

            HttpRequestFilter Filter = new HttpRequestFilter();
            Header.URL = Filter.URLFilter(Header.URL);                                      //过滤URL特殊字符
            if (Header.URL == "URL字符过滤异常")
            {
                GetMethodResult.ResultReport = Header.URL;
                return GetMethodResult;
            }

            GetMethodResult.ResultReport = "请求过滤成功";
            return GetMethodResult;
        }

    }
}