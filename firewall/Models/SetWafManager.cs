using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace firewall.Models
{
    public class SetWafManager
    {
        [Key]
        public int id { get; set; }

        [Required]
        [MaxLength(15)]
        public string Visitor_IP { get; set; }

        [RegularExpression("^[0-9]{0,8}$")]
        public string  Flow_TotalRate{ get; set; }
        [RegularExpression("^[0-9]{0,3}$")]
        public string Visitor_TotalRate { get; set; }
        public Boolean Visit_Limit { get; set; }       
    }

    //该类用于处理用户设置防火墙功能的历史和设置
    public class CompleteLimitList
    {
        //调用方法设置用户的防火墙功能设置并返回执行结果
        public string CompleteLimitResult(SetWafManager SetLimitRequest)
        {
            return CompleteSetting(SetLimitRequest);
        }

        //调用方法获取用户的防火墙功能设置并返回执行结果
        public string[] GetLimitSettings()
        {
            return GetLimitList();
        }

        //执行防火墙功能的数据库设置
        private string CompleteSetting(SetWafManager SetLimitRequest)
        {
            Boolean Result=true;
            LimitList LimitSetting = new LimitList();
            string HostIp = SetLimitRequest.Visitor_IP;
            int Flow_TotalRate = (SetLimitRequest.Flow_TotalRate == null ? 0 : int.Parse(SetLimitRequest.Flow_TotalRate));
            int Visitor_TotalRate =(SetLimitRequest.Visitor_TotalRate == null ? 0:int.Parse(SetLimitRequest.Visitor_TotalRate));
            Boolean Visit_Limit = SetLimitRequest.Visit_Limit;

            if (string.IsNullOrEmpty(HostIp))
                return "IP地址不能为空";

            if (Flow_TotalRate > 0)
                Result = LimitSetting.SetFlowTotalRate(HostIp, Flow_TotalRate);
            if (!Result || Flow_TotalRate <0)
                return "流量设置出错";

            if (Visitor_TotalRate > 0)
                Result = LimitSetting.SetVisitorTotalRate(HostIp, Visitor_TotalRate);
            if (!Result || Visitor_TotalRate <0)
                return "访问频率设置出错";

            if (Visit_Limit == true || Visit_Limit == false)
                Result = LimitSetting.SetLimitVisitor(HostIp, Visit_Limit);
            if (!Result)
                return "名单限制设置失败";

            return "设置成功";
        }

        //调用方法执行获取数据库中防火墙功能设置历史的记录
        private string[] GetLimitList()
        {
            LimitList LimitSetting = new LimitList();
            return LimitSetting.GetLimitDataList();
        }



    }

}