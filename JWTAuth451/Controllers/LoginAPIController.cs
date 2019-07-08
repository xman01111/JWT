using JWTAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using System.Web.Http;

namespace JWTAuth451.Controllers
{
    
    /// <summary>
    /// 登录api
    /// </summary>
    public class LoginAPIController : ApiController
    {
        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        [HttpPost, AllowAnonymous, Route("LoginAPI/LoginTest")]
        public IHttpActionResult LoginTest(string userName,string Password)
        {
            AjaxResult<string> result = new AjaxResult<string>();
            if (LoginHelper.Checked(userName, Password))
            {
                Dictionary<string, object> payLoad = new Dictionary<string, object>();
                payLoad.Add("sub", "user");
                payLoad.Add("jti", Guid.NewGuid().ToString());
                payLoad.Add("nbf", null);
                payLoad.Add("exp", null);
                payLoad.Add("iss", "Issuser");
                payLoad.Add("aud", "user");
                payLoad.Add("user", userName);
                var token = TokenManager.CreateToken(payLoad, 30);
                result.status = ResultStatus.OK;
                result.msg = "登录成功";
                result.Data = token;
                var cookie = new HttpCookie("MRCToken");
                cookie.Expires = DateTime.Now.AddDays(1);
                cookie.Domain = Request.RequestUri.Host;
                cookie.Path = "/";
                cookie.Value = token;
                CacheHelper.Set("userToken:"+userName,token.ToMD5());//应放在redis 防止重启站点丢失 或者多站点情况下 无法共享
                HttpContext.Current.Response.AppendCookie(cookie);
            }
            else
            {
                result.status = ResultStatus.Failed;
                result.msg = "登录失败";
            }
            return Json(result);
        }
        /// <summary>
        /// 测试登录
        /// </summary>
        /// <returns></returns>
         [HttpPost,Login, Route("LoginAPI/TestLoginStatus")]
          
        public IHttpActionResult TestLoginStatus()
        {
            return Json("OK");
        }
    }
}