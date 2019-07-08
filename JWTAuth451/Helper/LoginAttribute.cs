using JWTAuth;
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using System.Linq;
namespace JWTAuth451
{
    /// <summary>
    /// 登录过滤
    /// </summary>
    public class LoginAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            bool validateResult = false;
            HttpRequest request = HttpContext.Current.Request;
            if (actionContext.ActionDescriptor.GetCustomAttributes<AllowAnonymousAttribute>().Any())
            {
                return;
            }
            //尝试从header中获取
            var token = request.Headers["MRCToken"];
            if (token == null || token == "")
            {
                //尝试从cookies中获取 
                var loginCookie = request.Cookies["MRCToken"];
                if (loginCookie != null)
                {
                    token = loginCookie.Value;
                }
            }
            if (token != null && token != "")
            {
                //验证token
                validateResult = TokenManager.Validate(token, payLoad =>
                {
                    var success = true;
                    //验证授权标识
                    success = success && payLoad["aud"]?.ToString() == "user";                    
                    var cacheToken=CacheHelper.Get("userToken:" + payLoad["user"]);
                    //验证与缓存中token是否匹配（单点登录和判断有效性） 多站点应放在redis
                    if (cacheToken==null||cacheToken.ToString()==""||cacheToken.ToString()!=token.ToMD5()) success = false;
                    return success;
                });
            }
            if (!validateResult)
            {
                Valid(actionContext);
            }
            base.OnActionExecuting(actionContext);
        }
        private HttpActionContext Valid(HttpActionContext filterContext)
        {
            var response= filterContext.Request.CreateResponse(HttpStatusCode.InternalServerError);         
            filterContext.Response = response;
            AjaxResult result = AjaxResult.CreateResult(ResultStatus.NotLogin, "未登录或登录超时，请重新登录");
            filterContext.Response.Content =new StringContent(JsonHelper.Serialize(result), Encoding.GetEncoding("UTF-8"), "application/json");         
            return filterContext;
        }
    }
    /// <summary>
    /// 不验证登录
    /// </summary>
    public class AllowAnonymousAttribute : ActionFilterAttribute
    {

    }
}
