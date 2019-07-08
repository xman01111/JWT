using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuth451
{
    public class AjaxResult
    {
        ResultStatus _status = ResultStatus.OK;
        public AjaxResult()
        {
        }
        public AjaxResult(ResultStatus status)
        {
            this._status = status;
        }

        public AjaxResult(ResultStatus status, string msg)
        {
            this.status = status;
            this.msg = (msg);
        }

        public ResultStatus status { get { return this._status; } set { this._status = value; } }
        public string msg { get; set; }

        public static AjaxResult CreateResult(string msg = null)
        {
            AjaxResult result = CreateResult(ResultStatus.OK, msg);
            return result;
        }
        public static AjaxResult CreateResult(ResultStatus status, string msg = null)
        {
            AjaxResult result = new AjaxResult(status);
            result.msg = (msg);//转化为选择的语言版本
            return result;
        }
        public static AjaxResult<T> CreateResult<T>(T data)
        {
            AjaxResult<T> result = CreateResult<T>(ResultStatus.OK, data);
            return result;
        }
        public static AjaxResult<T> CreateResult<T>(ResultStatus status)
        {
            AjaxResult<T> result = CreateResult<T>(status, default(T));
            return result;
        }
        public static AjaxResult<T> CreateResult<T>(ResultStatus status, T data)
        {
            AjaxResult<T> result = new AjaxResult<T>(status);
            result.Data = data;
            return result;
        }
        public static AjaxResult<T> CreateResult<T>(ResultStatus status,string msg, T data)
        {
            AjaxResult<T> result = new AjaxResult<T>(status);
            result.Data = data;
            result.msg = (msg);
            return result;
        }
    }
    public class AjaxResult<T> : AjaxResult
    {
        public AjaxResult()
        {
        }
        public AjaxResult(ResultStatus status)
            : base(status)
        {
        }
        public AjaxResult(ResultStatus status, T data)
            : base(status)
        {
            this.Data = data;
        }
        public T Data { get; set; }
    }
    public enum ResultStatus
    {
        OK = 200,
        Failed = 500,
        /// <summary>
        /// 表示未登录
        /// </summary>
        NotLogin = 102,
        /// <summary>
        /// 表示未授权
        /// </summary>
        Unauthorized = 103,
    }
}
