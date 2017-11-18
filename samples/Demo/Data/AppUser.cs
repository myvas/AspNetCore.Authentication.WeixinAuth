using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Demo.Data
{
    public class AppUser : IdentityUser<string>
    {
        public AppUser()
        {
            Id = ShortGuid.NewGuid().ToString();
        }
    }
}
