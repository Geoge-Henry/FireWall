using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace firewall.Models
{
    //该类用于转发客户端请求到真实服务器,并获取真实服务器结果
    public class SendToRealServer
    {
        //定义该结构体作为真实服务器的Response结果
        public struct ResponseResult
        {
            public HttpWebResponse ResponseList { get; set; }
            public string ResponseContents { get; set; }
            public string ResponseReport { get; set; }
        }

        //调用方法获取POST请求的真实服务器响应
        public ResponseResult GetResponse(Home.AnalyzeResult AnalyzeResult)
        {
            return Send(AnalyzeResult);
        }

        //调用方法获取GET请求的真实服务器响应
        public ResponseResult GetResponseByGet(Home.AnalyzeResult AnalyzeResult)
        {
            return SendByGet(AnalyzeResult);
        }

        //转发报文,并获取真实服务器的响应报文--POST请求
        private ResponseResult Send(Home.AnalyzeResult AnalyzeResult)
        {
            ResponseResult responseresult = new ResponseResult();
            try
            {
                //添加checknum字段用于标识该请求来源于防火墙已过滤的请求
                string postData =  AnalyzeResult.RequestContents.ToString()+"&checknum=321";
                byte[] byteArray = Encoding.UTF8.GetBytes(postData);
                string url = "http://mymvclogindemo.top/MVCDemo/Home";
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(new Uri(url));

                //添加请求的客户端cookie
                if (AnalyzeResult.RequestHeader.Cookies.Count != 0)
                {
                    CookieCollection CookiesArray = new CookieCollection();
                    Cookie Cookie = new Cookie();
                    foreach (string CookieKey in AnalyzeResult.RequestHeader.Cookies.Keys)
                    {
                        Cookie.Name = CookieKey;
                        Cookie.Value = AnalyzeResult.RequestHeader.Cookies[CookieKey];
                        CookiesArray.Add(Cookie);
                    }
                    webRequest.CookieContainer = new CookieContainer();
                    if (CookiesArray.Count > 1)
                        webRequest.CookieContainer.Add(CookiesArray);
                }
                webRequest.Method = "POST";
                webRequest.ContentType = AnalyzeResult.RequestHeader.ContentType;
                webRequest.ContentLength = byteArray.Length;
                Stream newStream = webRequest.GetRequestStream();
                newStream.Write(byteArray, 0, byteArray.Length);
                newStream.Close();

                //获取响应报文并格式化
                HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse();
                responseresult.ResponseList = response;               
                StreamReader Message = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                responseresult.ResponseContents = Message.ReadToEnd();
                responseresult.ResponseReport = "读取成功";
                return responseresult;
            }
            catch
            {
                responseresult.ResponseReport = "读取失败";
                return responseresult;
            }
        }


        //转发报文,并获取真实服务器的响应报文--GET请求
        private ResponseResult SendByGet(Home.AnalyzeResult AnalyzeResult)
        {
            ResponseResult responseresult = new ResponseResult();
            try
            {
                //string postData = AnalyzeResult.RequestContents.ToString();--GET请求不必发送正文
                //byte[] byteArray = Encoding.UTF8.GetBytes(postData);
                string url = "http://mymvclogindemo.top/MVCDemo";
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(new Uri(url));

                //添加请求的客户端cookie
                if (AnalyzeResult.RequestHeader.Cookies.Count != 0)
                {
                    CookieCollection CookiesArray = new CookieCollection();
                    Cookie Cookie = new Cookie();
                    foreach (string CookieKey in AnalyzeResult.RequestHeader.Cookies.Keys)
                    {
                        Cookie.Name = CookieKey;
                        Cookie.Value = AnalyzeResult.RequestHeader.Cookies[CookieKey];
                        CookiesArray.Add(Cookie);
                    }
                    webRequest.CookieContainer = new CookieContainer() ;
                    if(CookiesArray.Count >1)
                    webRequest.CookieContainer.Add(CookiesArray);
                }
                webRequest.Method = "GET";
                webRequest.ContentType = AnalyzeResult.RequestHeader.ContentType;
                //webRequest.ContentLength = byteArray.Length;
     
                //获取响应报文并格式化
                HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse();
                responseresult.ResponseList = response;
                StreamReader Message = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                responseresult.ResponseContents = Message.ReadToEnd();
                responseresult.ResponseReport = "读取成功";
                return responseresult;
            }
            catch
            {
                responseresult.ResponseReport = "读取失败";
                return responseresult;
            }
        }

    }
}