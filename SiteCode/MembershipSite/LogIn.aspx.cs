using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Net;
using System.Web.UI.WebControls;
using System.Text;
using System.Collections.Specialized;
using System.Web.Security;
using System.Security.Cryptography;
using System.Data.SqlClient;
using HashLibrary;
using System.Configuration;
using System.Text.RegularExpressions;

namespace MembershipSite
{
    public partial class LogInPage : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
        }

        public bool IsAlphaNumeric(string text)
        {
            return Regex.IsMatch(text, "^[a-zA-Z0-9]+$");
        }

        protected void LoginControl_Authenticate(object sender, AuthenticateEventArgs e)
        {
            bool authenticated = this.ValidateCredentials(LoginControl.UserName, LoginControl.Password);

            if (authenticated)
            {
                FormsAuthentication.RedirectFromLoginPage(LoginControl.UserName, LoginControl.RememberMeSet);
            }
        }


        static string sha1hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    // can be "x2" if you want lowercase
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }

        private bool ValidateCredentials(string userName, string password)
        {
            bool returnValue = false;

            //Originally, there was a check in this If statement with the function: "isAlphaNumeric()"
            //This worked by disallowing special characters in the username field, so we removed it to make it vulnerable...

            if (userName.Length <= 50 && password.Length <= 50)
            {
                SqlConnection conn = null;

                try
                {
                    string sql = "select count(*) from users where username = '@username' and password = '@password'";

                    sql = sql.Replace("@username", userName);
                    sql = sql.Replace("@password", sha1hash(password));

                    conn = new SqlConnection(ConfigurationManager.ConnectionStrings["MembershipSiteConStr"].ConnectionString);
                    SqlCommand cmd = new SqlCommand(sql, conn);

                    //Removing parameterization to make it vulnerable to SQL Injection
                    //Otherwise the SQL Engine will parse out these parameters in memory, and not as a part of an executable statement

                    /*
                    SqlParameter user = new SqlParameter();
                    user.ParameterName = "@username";
                    user.Value = userName.Trim();
                    cmd.Parameters.Add(user);

                    SqlParameter pass = new SqlParameter();
                    pass.ParameterName = "@password";
                    pass.Value = Hasher.HashString(password.Trim());
                    cmd.Parameters.Add(pass);
                    */



                    conn.Open();

                    int count = (int)cmd.ExecuteScalar();
                    

                    if (count > 0)
                    {
                        sql = "select * from users where username = '@username' and password = '@password'";
                        sql = sql.Replace("@username", userName);
                        sql = sql.Replace("@password", sha1hash(password));
                        cmd = new SqlCommand(sql, conn);
                        SqlDataReader reader = cmd.ExecuteReader();

                       // var resp = new HttpResponseMessage();
                        var userinfo = new HttpCookie("userInfo");

                        while (reader.Read())
                        {
                            userinfo["username"] = reader[0].ToString();
                            Response.Cookies.Add(userinfo);
                        }

                        //hide login form
                        //store user cookie
                        //give logout button
                        //show username
                        returnValue = true;
                    }

                    conn.Close();

                }
                catch (Exception ex)
                {
                    Trace.Write(ex.Message);
                }
                finally
                {
                    if (conn != null) conn.Close();
                }
            }
            else
            {
                // Log error - user name not alpha-numeric or 
                // username or password exceed the length limit!
            }

            return returnValue;
        }
    }
}
