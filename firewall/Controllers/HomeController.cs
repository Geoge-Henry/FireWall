using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Net;
using System.IO;
using firewall.Models;

namespace firewall.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        public string Index()
        {
            //对GET请求进行报文分析、过滤
            Home AnalyzeRequest = new Home();
            Home.AnalyzeResult AnalyzeResult = AnalyzeRequest.GetGetRequestResult(Request);

            //实例化日志记录DBRecords类
            DBRecords DBRecord = new DBRecords();

            if (AnalyzeResult.ResultReport != "请求过滤成功")
            {
                if (!DBRecord.InsertIntoDB(AnalyzeResult))  //将请求记录入数据库并返回成功或失败
                    AnalyzeResult.ResultReport = AnalyzeResult.ResultReport + "日志更新失败";
                return AnalyzeResult.ResultReport;          //返回此次请求通过失败的报告
            }
            else
            {
                //实例化转发到真实服务器的SendToRealServer的类,并执行转发
                SendToRealServer SendMessage = new SendToRealServer();
                SendToRealServer.ResponseResult SendResult = SendMessage.GetResponseByGet(AnalyzeResult);

                if (!DBRecord.InsertIntoDB(AnalyzeResult))      //将请求记录入数据库并返回成功或失败
                    AnalyzeResult.RequestContents = AnalyzeResult.RequestContents + "日志更新失败";

                if (SendResult.ResponseReport != "读取成功")
                {
                    return SendResult.ResponseReport;           //将转发失败的报告返回
                }
                else
                {
                    return SendResult.ResponseContents+"已经过防火墙";    //将成功的Response返回给客户端
                }            
            }

        }


        [HttpPost]
        public string Index(string Method=null)
        {
            //对POST请求进行报文分析、过滤
            Home AnalyzeRequest = new Home();
            Home.AnalyzeResult AnalyzeResult = AnalyzeRequest.GetPostRequestResult(Request);

            //实例化日志记录DBRecords类
            DBRecords DBRecord = new DBRecords();

            if (AnalyzeResult.ResultReport != "请求过滤成功")    
            {
                if (!DBRecord.InsertIntoDB(AnalyzeResult))      //将请求记录入数据库并返回成功或失败
                    AnalyzeResult.ResultReport = AnalyzeResult.ResultReport + "日志更新失败";
                return AnalyzeResult.ResultReport;              //返回此次请求通过失败的报告
            }
            else
            {
                //实例化转发到真实服务器的SendToRealServer的类,并执行转发
                SendToRealServer SendMessage = new SendToRealServer();
                SendToRealServer.ResponseResult SendResult = SendMessage.GetResponse(AnalyzeResult);

                if (!DBRecord.InsertIntoDB(AnalyzeResult))      //将请求记录入数据库并返回成功或失败
                    AnalyzeResult.RequestContents = AnalyzeResult.RequestContents + "日志更新失败";

                if (SendResult.ResponseReport != "读取成功")
                {
                    return SendResult.ResponseReport;            //将转发失败的报告返回
                }
                else
                {
                    return "请求内容：" + SendResult.ResponseContents + "-----从真实服务器返回";  //将成功的Response返回给客户端
                }
            }

        }



    }
}
