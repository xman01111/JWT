using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JWTAuth451
{
    public class LoginHelper
    {

        public static bool Checked(string userName, string password)
        {
            if (userName == "admin" && password == "111111") return true;
            return false;            
        }
    
    }
}