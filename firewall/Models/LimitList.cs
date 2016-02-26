using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using MySql;
using MySql.Data.MySqlClient;

namespace firewall.Models
{
    //该类用于在数据库中处理用户设置防火墙功能的请求
    public class LimitList
    {
        //连接数据库
        private static String mysqlcon = ConfigurationManager.ConnectionStrings["VisitorInfo"].ConnectionString;
        private MySqlConnection conn;
        private MySqlCommand comm;

        //判断是否是黑名单的IP
        public Boolean IsLimitVisitor(string HostIp)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return false;
                conn.Open();
                comm = new MySqlCommand();
                comm.CommandText = "select Visit_Limit from visitor_limit where Visitor_IP=" + "\"" + HostIp + "\"";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                if (!SelectResult.Read())
                    return true;
                else if ((Boolean)SelectResult["Visit_Limit"])
                    return false;
                else
                    return true;
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

        //获取访问频率限制额
        public int GetLimitVisitorTotalRate(string HostIp)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return 0;
                conn.Open();
                comm = new MySqlCommand();
                comm.CommandText = "select Visitor_TotalRate from visitor_limit where Visitor_IP=" + "\"" + HostIp + "\"";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                if (!SelectResult.Read())
                    return -1;
                else
                {
                    return int.Parse(SelectResult["Visitor_TotalRate"].ToString());
                }
            }
            catch
            {
                return 0;
            }
            finally
            {
                comm.Dispose();
                conn.Close();
            }
        }

        //获取访问流量限制额
        public int GetLimitFlowTotalRate(string HostIp)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return 0;
                conn.Open();
                comm = new MySqlCommand();
                comm.CommandText = "select Flow_TotalRate from visitor_limit where Visitor_IP=" + "\"" + HostIp + "\"";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                if (!SelectResult.Read())
                    return -1;
                else
                {
                    return int.Parse(SelectResult["Flow_TotalRate"].ToString());
                }
            }
            catch
            {
                return 0;
            }
            finally
            {
                comm.Dispose();
                conn.Close();
            }
        }

        //设置访问的黑名单IP
        public Boolean SetLimitVisitor(string HostIp,Boolean IsLimit)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return false;
                conn.Open();
                comm = new MySqlCommand();
                //先判断该IP是否存在,在决定进行insert或update
                comm.CommandText = "select * from visitor_limit where Visitor_IP=" + "\"" + HostIp + "\"";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                if (!SelectResult.Read())
                {
                SelectResult.Close();
                comm.CommandText = "insert into visitor_limit(id,Visitor_IP,Visit_Limit) value(null,@Visitor_IP,@Visit_Limit)";
                MySqlParameter p1 = new MySqlParameter("@Visitor_IP",HostIp);
                comm.Parameters.Add(p1);
                MySqlParameter p2 = new MySqlParameter("@Visit_Limit", IsLimit);
                comm.Parameters.Add(p2);
                comm.ExecuteNonQuery();
                }
                else
                {
                    SelectResult.Close();
                    comm.CommandText = "update visitor_limit set Visit_Limit=@Visit_Limit where Visitor_IP=" + "\"" + HostIp + "\"";
                    MySqlParameter p1 = new MySqlParameter("@Visit_Limit", IsLimit);
                    comm.Parameters.Add(p1);
                    comm.ExecuteNonQuery();
                }
                return true;
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

        //设置用户访问频率额
        public Boolean SetVisitorTotalRate(string HostIp,int TotalRate)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return false;
                conn.Open();
                comm = new MySqlCommand();
                //先判断该IP是否存在,在决定进行insert或update
                comm.CommandText = "select * from visitor_limit where Visitor_IP=" + "\"" + HostIp + "\"";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                if (!SelectResult.Read())
                {
                    SelectResult.Close();
                    comm.CommandText = "insert into visitor_limit(id,Visitor_IP,Visitor_TotalRate) " +
                    "value(null,@Visitor_IP,@Visitor_TotalRate)";
                    MySqlParameter p1 = new MySqlParameter("@Visitor_IP", HostIp);
                    comm.Parameters.Add(p1);
                    MySqlParameter p2 = new MySqlParameter("@Visitor_TotalRate", TotalRate);
                    comm.Parameters.Add(p2);
                    comm.ExecuteNonQuery();
                }
                else
                {
                    SelectResult.Close();
                    comm.CommandText = "update visitor_limit set Visitor_TotalRate=@Visitor_TotalRate " +
                        "where Visitor_IP=" + "\"" + HostIp + "\"";
                    MySqlParameter p1 = new MySqlParameter("@Visitor_TotalRate", TotalRate);
                    comm.Parameters.Add(p1);
                    comm.ExecuteNonQuery();
                }
                return true;
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

        //设置访问流量限制额
        public Boolean SetFlowTotalRate(string HostIp, int TotalRate)
        {
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                    return false;
                conn.Open();
                comm = new MySqlCommand();
                //先判断该IP是否存在,在决定进行insert或update
                comm.CommandText = "select * from visitor_limit where Visitor_IP=" + "\"" + HostIp + "\"";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                if (!SelectResult.Read())
                {
                    SelectResult.Close();
                    comm.CommandText = "insert into visitor_limit(id,Visitor_IP,Flow_TotalRate) " +
                    "value(null,@Visitor_IP,@Flow_TotalRate)";
                    MySqlParameter p1 = new MySqlParameter("@Visitor_IP", HostIp);
                    comm.Parameters.Add(p1);
                    MySqlParameter p2 = new MySqlParameter("@Flow_TotalRate", TotalRate);
                    comm.Parameters.Add(p2);
                    comm.ExecuteNonQuery();
                }
                else
                {
                    SelectResult.Close();
                    comm.CommandText = "update visitor_limit set Flow_TotalRate=@Flow_TotalRate " +
                        "where Visitor_IP=" + "\"" + HostIp + "\"";
                    MySqlParameter p1 = new MySqlParameter("@Flow_TotalRate", TotalRate);
                    comm.Parameters.Add(p1);
                    comm.ExecuteNonQuery();
                }
                return true;
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

        //获取用户设置的历史记录
        public string[] GetLimitDataList()
        {
            string[] Result=new string[50];
            int num=1;
            try
            {
                conn = new MySqlConnection(mysqlcon);
                if (conn.State == System.Data.ConnectionState.Open)
                {
                    Result[0] = "数据库异常";
                    return Result;
                }
                conn.Open();
                comm = new MySqlCommand();
                comm.CommandText = "select * from visitor_limit limit 10";
                comm.Connection = conn;
                comm.ExecuteNonQuery();
                MySqlDataReader SelectResult = comm.ExecuteReader();
                Result[0] = "读取成功";
                while (SelectResult.Read())
                {
                    //格式化,便于前端显示
                    Result[num] = SelectResult["id"].ToString();
                    Result[num + 1] = SelectResult["Visitor_IP"].ToString();
                    Result[num + 2] = SelectResult["Flow_TotalRate"].ToString();
                    Result[num + 3] = SelectResult["Visitor_TotalRate"].ToString();
                    Result[num + 4] = SelectResult["Visit_Limit"].ToString();
                    num=num+5;
                }
                return Result;
            }
            catch
            {
                Result[0]="无法读取近期的设置数据";
                return Result;
            }
            finally
            {
                comm.Dispose();
                conn.Close();
            }
        }



    }
}