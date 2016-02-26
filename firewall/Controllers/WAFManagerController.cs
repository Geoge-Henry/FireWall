using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using firewall.Models;

namespace firewall.Controllers
{
    public class WAFManagerController : Controller
    {
        //处理GET请求
        [HttpGet]
        public ActionResult Index()
        {
            //实例化CompleteLimitList类,以用于处理用户设置防火墙的历史
            CompleteLimitList completelimitlist = new CompleteLimitList();

            //将设置历史进行格式转换，存入ViewData,供前端显示
            string[] DataResult = new string[50];           //用于存储设置历史的Data记录
            int num = 0;
            DataResult = completelimitlist.GetLimitSettings();
            if (DataResult[0] == "读取成功")
            {
                while (DataResult[num] != null && DataResult[num + 1] != null)
                {
                    DataResult[num] = DataResult[num + 1];
                    num++;
                }
                DataResult[num] = null;
                ViewData["row"] = num;
                ViewData["Data"] = DataResult;
            }
            else
                ViewData["Data"] = "错误";
            return View();
        }

        //处理POST请求
        [HttpPost]
        public string Index(SetWafManager SetLimitRequest)
        {
            //对POST请求进行报文分析、过滤
            Home AnalyzeRequest = new Home();
            firewall.Models.Home.AnalyzeResult AnalyzeResult = AnalyzeRequest.GetPostRequestResult(Request);
            if (AnalyzeResult.ResultReport == "请求过滤成功")
            {
                CompleteLimitList completelimitlist = new CompleteLimitList();  //成功时将该请求执行,并存入设置历史
                return completelimitlist.CompleteLimitResult(SetLimitRequest);
            }
            else if (AnalyzeResult.ResultReport == "该主机已被设置为黑名单，无法访问")
            {
                CompleteLimitList completelimitlist = new CompleteLimitList();  //若已被设置为黑名单,则强制执行更改并存入设置历史
                return completelimitlist.CompleteLimitResult(SetLimitRequest);
            }
            else
            {
                return AnalyzeResult.ResultReport;                              //若设置失败,返回失败报告
            }
        }

        //该Search页面用于显示近期访问防火墙的用户记录
        [HttpGet]
        public ActionResult Search()
        {
            //将日志从数据库中提取出来显示在前端
            DBRecords DBRecord = new DBRecords();
            ViewData["DBJournal"] = DBRecord.GetJournal();      
            return View();
        }

    }
}
