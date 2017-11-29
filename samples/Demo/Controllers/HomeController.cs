using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AspNetCore.WeixinOAuth.Demo.Models;
using AspNetCore.WeixinOAuth.Demo.Models.HomeViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace AspNetCore.WeixinOAuth.Demo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            var feature = HttpContext.Features.Get<IExceptionHandlerFeature>();
            var error = feature?.Error;

            if (error != null)
            {
                _logger.LogError(error.Message, error);
            }

            return View(
                new ErrorViewModel
                {
                    RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                    Error = error
                });
        }
        public IActionResult ShowQrcode(string redirectUrl)
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> UserInfo()
        {
            var model = new UserInfoViewModel()
            {
                IsAuthenticated = HttpContext.User.Identity.IsAuthenticated,
                UserName = HttpContext.User.Identity.Name,

                //1.Claims for Identity:
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier : 7668444a-9d51-4a01-8a2f-e899812db37b
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name : 15902059380
                //AspNet.Identity.SecurityStamp : 75a48aaa - 0276 - 40f0 - 9167 - 6bd49f0c5327
                //2.Claims for Identity associated with WeixinOAuth:
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier :
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name :
                //AspNet.Identity.SecurityStamp : 
                //http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod : Weixin-OAuth

                Claims = HttpContext.User.Claims,
                AccessToken = await HttpContext.GetTokenAsync("access_token"),
                RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
                ExpiresAt = await HttpContext.GetTokenAsync("expires_at"),
                TokenType = await HttpContext.GetTokenAsync("token_type"),
            };
            return View(model);
        }


    }
}
