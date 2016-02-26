using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text.RegularExpressions;
using System.Globalization;

namespace firewall.Models
{
    public class HttpRequestFilter
    {
        public string HTMLFilter(string Htmlstring)                             //该方法用于过滤HTML标签
        {
            try
            {
                //删除脚本
                Htmlstring = Regex.Replace(Htmlstring, @"<script[^>]*?>.*?</script>", "",
                  RegexOptions.IgnoreCase);
                //删除HTML
                Htmlstring = Regex.Replace(Htmlstring, @"<(.[^>]*)>", "",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"([\r\n])[\s]+", "",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"-->", "", RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"<!--.*", "", RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(quot|#34);", "\"",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(amp|#38);", "&",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(lt|#60);", "<",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(gt|#62);", ">",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(nbsp|#160);", "   ",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(iexcl|#161);", "\xa1",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(cent|#162);", "\xa2",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(pound|#163);", "\xa3",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&(copy|#169);", "\xa9",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, @"&#(\d+);", "",
                  RegexOptions.IgnoreCase);
                Htmlstring = Regex.Replace(Htmlstring, "xp_cmdshell", "",
                  RegexOptions.IgnoreCase);

                Htmlstring.Replace("<", "");
                Htmlstring.Replace(">", "");
                Htmlstring.Replace("\r\n", "");
                return Htmlstring;
            }
            catch
            {
                return "HTML标签过滤异常";
            }
           
        }

        public string SpecialCharFilter(string Input)
        {
            try
            {
                //单引号替换成两个单引号
                Input = Input.Replace("'", "''");
                //半角封号替换为全角封号，防止多语句执行
                Input = Input.Replace("?", "");
                Input = Input.Replace(",", "");
                Input = Input.Replace("/", "");
                Input = Input.Replace(";", "");
                Input = Input.Replace("*/", "");

                //半角括号替换为全角括号
                Input = Input.Replace("(", "（");
                Input = Input.Replace(")", "）");

                ///////////////要用正则表达式替换，防止字母大小写得情况////////////////////

                //去除执行存储过程的命令关键字
                Input = Input.Replace("Exec", "");
                Input = Input.Replace("Execute", "");

                //去除系统存储过程或扩展存储过程关键字
                Input = Input.Replace("xp_", "x p_");
                Input = Input.Replace("sp_", "s p_");

                //防止16进制注入
                Input = Input.Replace("0x", "0 x");
                return Input;
            }
            catch
            {
                return "特殊字符过滤异常";
            }
        }

        public string SqlFilter(string Input)
        {
            try
            {
                Input = Regex.Replace(Input, "(select )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "(insert )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "delete from", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "(count'')", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "drop table", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "(truncate )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( asc )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( mid )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( char )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "xp_cmdshell", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "(exec master)", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "net localgroup administrators", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( and )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "net user", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( or )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( net )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( - )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( delete )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( drop )", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "( script )", "", RegexOptions.IgnoreCase);
                return Input;
            }
            catch
            {
                return "SQL字符过滤异常";
            }
        }

        /// <summary>    
        /// 过滤xss攻击脚本    
        /// </summary>    
        /// <param name="input">传入字符串</param>    
        /// <returns>过滤后的字符串</returns>    
        public string XSSFilter(string Input)
        {
            if (string.IsNullOrEmpty(Input)) return string.Empty;

            try
            {
                // CR(0a) ，LF(0b) ，TAB(9) 除外，过滤掉所有的不打印出来字符.    
                // 目的防止这样形式的入侵 ＜java\0script＞    
                // 注意：\n, \r,  \t 可能需要单独处理，因为可能会要用到    
                string ret = Regex.Replace(Input, "([\x00-\x08][\x0b-\x0c][\x0e-\x20])", string.Empty);

                //替换所有可能的16进制构建的恶意代码    
                //<IMG SRC=&#X40&#X61&#X76&#X61&#X73&#X63&#X72&#X69&#X70&#X74
                //&#X3A&#X61&_#X6C&#X65&#X72&#X74&#X28&#X27&#X58&#X53&#X53&#X27&#X29>    
                string chars = "abcdefghijklmnopqrstuvwxyz" +
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" +
                            "!@#$%^&*()~`;:?+/={}[]-_|'\"\\";
                for (int i = 0; i < chars.Length; i++)
                {
                    ret = Regex.Replace(ret, string.Concat("(&#[x|X]0{0,}",
                                Convert.ToString((int)chars[i], 16).ToLower(), ";?)"),
                            chars[i].ToString(), RegexOptions.IgnoreCase);
                }

                //过滤\t, \n, \r构建的恶意代码  
                string[] keywords = {"javascript", "vbscript", "expression",
                "applet", "meta", "xml", "blink", "link", "style",
                "script", "embed", "object", "iframe", "frame",
                "frameset", "ilayer", "layer", "bgsound", "title",
                "base" ,"onabort", "onactivate", "onafterprint",
                "onafterupdate", "onbeforeactivate", "onbeforecopy",
                "onbeforecut", "onbeforedeactivate", "onbeforeeditfocus",
                "onbeforepaste", "onbeforeprint", "onbeforeunload",
                "onbeforeupdate", "onblur", "onbounce", "oncellchange",
                "onchange", "onclick", "oncontextmenu", "oncontrolselect",
                "oncopy", "oncut", "ondataavailable", "ondatasetchanged",
                "ondatasetcomplete", "ondblclick", "ondeactivate",
                "ondrag", "ondragend", "ondragenter", "ondragleave",
                "ondragover", "ondragstart", "ondrop", "onerror",
                "onerrorupdate", "onfilterchange", "onfinish",
                "onfocus", "onfocusin", "onfocusout", "onhelp",
                "onkeydown", "onkeypress", "onkeyup", "onlayoutcomplete",
                "onload", "onlosecapture", "onmousedown", "onmouseenter",
                "onmouseleave", "onmousemove", "onmouseout", "onmouseover",
                "onmouseup", "onmousewheel", "onmove", "onmoveend",
                "onmovestart", "onpaste", "onpropertychange",
                "onreadystatechange", "onreset", "onresize",
                "onresizeend", "onresizestart", "onrowenter",
                "onrowexit", "onrowsdelete", "onrowsinserted",
                "onscroll", "onselect", "onselectionchange",
                "onselectstart", "onstart", "onstop", "onsubmit",
                "onunload"};

                bool found = true;
                while (found)
                {
                    var retBefore = ret;
                    for (int i = 0; i < keywords.Length; i++)
                    {
                        string pattern = "/";
                        for (int j = 0; j < keywords[i].Length; j++)
                        {
                            if (j > 0)
                                pattern = string.Concat(pattern,
                                    '(', "(&#[x|X]0{0,8}([9][a][b]);?)?",
                                    "|(&#0{0,8}([9][10][13]);?)?",
                                    ")?");
                            pattern = string.Concat(pattern, keywords[i][j]);
                        }
                        string replacement = string.Concat(keywords[i].Substring(0, 2), "＜x＞", keywords[i].Substring(2));
                        ret = Regex.Replace(ret, pattern, replacement, RegexOptions.IgnoreCase);
                        if (ret == retBefore)
                            found = false;
                    }
                }
                ret = ret.Trim();
                return ret;
            }
            catch
            {
                return "XSS过滤异常";
            }
        }


        //该方法用于过滤URL的不合法标签
        public string URLFilter(string Input)
        {
            try
            {
                Input = Regex.Replace(Input, @"<script[^>]*?>.*?</script>", "",
                  RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, @"<(.[^>]*)>", "",
                  RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, @"-->", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, @"<!--.*", "", RegexOptions.IgnoreCase);
                Input = Regex.Replace(Input, "xp_cmdshell", "", RegexOptions.IgnoreCase);
                Input.Replace("<", "");
                Input.Replace(">", "");
                Input = Input.Replace("Exec", "");
                Input = Input.Replace("Execute", "");
                Input = Regex.Replace(Input, @"(select )", "", RegexOptions.IgnoreCase);
                string SpecialString = "exec |insert |select |delete |update |count |chr |mid |master |truncate |char |declare ";
                string[] ErrorStrings = SpecialString.Split('|');
                foreach (string EachString in ErrorStrings)
                {
                    if (Input.ToLower().IndexOf(EachString) >= 0)
                        Input = Regex.Replace(Input, @"(" + EachString + ")", "", RegexOptions.IgnoreCase);
                }
                return Input;
            }
            catch
            {
                return "URL字符过滤异常";
            }
        }
        //SqlStr = "exec |insert |select |delete |update |count |chr |mid |master |truncate |char |declare "; 
        //else
        //SqlStr = "'|and|exec|insert|select|delete|update|count|*|chr|mid|master|truncate|char|declare"; 


    }
}