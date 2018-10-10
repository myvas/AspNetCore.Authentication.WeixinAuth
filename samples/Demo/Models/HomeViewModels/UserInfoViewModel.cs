using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Demo.Models
{
    public class UserInfoViewModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string TokenType { get; set; }
        public string ExpiresAt { get; set; }
        public ClaimsPrincipal User { get; set; }
        public ExternalLoginInfo ExternalLoginInfo { get; set; }
    }

}
