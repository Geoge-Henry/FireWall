using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace firewall.Models
{
    //该类用于处理用户访问防火墙的记录
    public class DBRecords
    {
        //连接数据库
        private static String mysqlcon = ConfigurationManager.ConnectionStrings["VisitorInfo"].ConnectionString;
        private MySqlConnection conn;
        private MySqlCommand comm;

        //获取每次访问的用户主要数据
        public struct RecordWords
        {
            public string URL { get; set; }                             //获取URL
            public string Method { get; set; }                          //获取传输方法GET、POST等
            public string HostIp { get; set; }                          //获取请求的主机IP地址
            public string Port { get; set; }                            //获取请求的端口号
            public int TotalBytes { get; set; }                         //获取请求内容的字节数（流量）
            public Boolean Visit_Limit { get; set; }                    //获取黑名单设置值
            public string Remarks { get; set; }                         //获取请求过滤结果信息
        }

        //提取用户的基本信息,调用方法将其存入数据库并返回成功或失败
        public Boolean InsertIntoDB(Home.AnalyzeResult AnalyzeResult)
        {
            RecordWords RecordWord = new RecordWords();
            RecordWord.HostIp = AnalyzeResult.RequestHeader.HostIp;
            RecordWord.Port = AnalyzeResult.RequestHeader.Port;
            RecordWord.Method = AnalyzeResult.RequestHeader.Method;
            RecordWord.URL = AnalyzeResult.RequestHeader.URL;
            RecordWord.TotalBytes = AnalyzeResult.RequestHeader.TotalBytes;
            if (AnalyzeResult.ResultReport == "该主机已被设置为黑名单，无法访问")
                RecordWord.Visit_Limit = true;
            else
                RecordWord.Visit_Limit = false;
            RecordWord.Remarks = AnalyzeResult.ResultReport;
            if (InsertRecord(RecordWord))
                return true;
            else
                return false;
        }

        //用于调用方法获取近期日志并返回调用结果
        public string[,] GetJournal()
        {
            return GetDBJournal();
        }

        //添加记录到数据库
        private Boolean InsertRecord(RecordWords RecordWord)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return false;
                conn.Open();
                comm = new MySqlCommand();
                comm.CommandText = "insert into visitor_record(id,Visitor_IP,Visitor_Port," +
                "Visitor_Method,Visitor_Url,Flow_Rate,Visitor_Time,Visitor_Limit,Remarks)" +
                " value(null,@Visitor_IP,@Visitor_Port,@Visitor_Method,@Visitor_Url,@Flow_Rate," +
                "@Visitor_Time,@Visitor_Limit,@Remarks)";
                comm.Connection = conn;
                MySqlParameter p1 = new MySqlParameter("@Visitor_IP", RecordWord.HostIp);
                comm.Parameters.Add(p1);
                MySqlParameter p2 = new MySqlParameter("@Visitor_Port", RecordWord.Port);
                comm.Parameters.Add(p2);
                MySqlParameter p3 = new MySqlParameter("@Visitor_Method", RecordWord.Method);
                comm.Parameters.Add(p3);
                MySqlParameter p4 = new MySqlParameter("@Visitor_Url", RecordWord.URL);
                comm.Parameters.Add(p4);
                MySqlParameter p5 = new MySqlParameter("@Flow_Rate", RecordWord.TotalBytes);
                comm.Parameters.Add(p5);
                MySqlParameter p6 = new MySqlParameter("@Visitor_Time", DateTime.Now);
                comm.Parameters.Add(p6);
                MySqlParameter p7 = new MySqlParameter("@Visitor_Limit", RecordWord.Visit_Limit);
                comm.Parameters.Add(p7);
                MySqlParameter p8 = new MySqlParameter("@Remarks", RecordWord.Remarks);
                comm.Parameters.Add(p8);
                if (comm.ExecuteNonQuery() > 0)
                    return true;
                else
                    return false;
            }
            catch
            {
                return false;
            }
            finally
            {
                comm.Dispose();
                conn.Close();
            }
        }

        //从数据库中获取近期日志记录
        private string[,] GetDBJournal()
        {
            int JournalRows=0;
            string[,] ErrorString=new string[0,0];
            string[,] JournalString = new string[10,9];
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return ErrorString;
                conn.Open();
                comm = new MySqlCommand();
                comm.CommandText = "select * from visitor_record order by id desc limit 10";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader JournalResult = comm.ExecuteReader();
                while (JournalResult.Read())
                {
                    //格式化处理,便于前端显示
                    JournalString[JournalRows,0] = JournalResult["id"].ToString()+"            ";
                    JournalString[JournalRows, 1] = JournalResult["Visitor_IP"].ToString() + "            ";
                    JournalString[JournalRows, 2] = JournalResult["Visitor_Port"].ToString() + "            ";
                    JournalString[JournalRows, 3] = JournalResult["Visitor_Method"].ToString() + "            ";
                    JournalString[JournalRows, 4] = JournalResult["Visitor_Url"].ToString() + "            ";
                    JournalString[JournalRows, 5] = JournalResult["Flow_Rate"].ToString() + "            ";
                    JournalString[JournalRows, 6] = JournalResult["Visitor_Time"].ToString() + "            ";
                    JournalString[JournalRows, 7] = JournalResult["Visitor_Limit"].ToString() + "            ";
                    JournalString[JournalRows, 8] = JournalResult["Remarks"].ToString() + "            ";
                    JournalRows++;
                    if (JournalRows == 10)
                        break;
                }

                return JournalString;
            }
            catch
            {
                return ErrorString;
            }
            finally
            {
                comm.Dispose();
                conn.Close();
            }
        }



    }
}