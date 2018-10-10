using AspNetCore.Authentication.WeixinOpen;
using Demo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Demo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger _logger;
        private readonly SignInManager<AppUser> _signInManager;

        public HomeController(
            SignInManager<AppUser> signInManager,
            ILogger<HomeController> logger)
        {
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
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
                AccessToken = await HttpContext.GetTokenAsync("access_token"),
                RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
                ExpiresAt = await HttpContext.GetTokenAsync("expires_at"),
                TokenType = await HttpContext.GetTokenAsync("token_type"),

                //1.Claims for Identity:
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier : 7668444a-9d51-4a01-8a2f-e899812db37b
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name : 15902059380
                //AspNet.Identity.SecurityStamp : 75a48aaa - 0276 - 40f0 - 9167 - 6bd49f0c5327

                //2.Claims for Identity associated with WeixinOpen:
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier : 187235f3-ed8c-47c9-8052-8a41417ebedb
                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name : 15902059380
                //AspNet.Identity.SecurityStamp : IWDARHGKWW5KJOBPMY4QMR4GSMEVRI5S
                //http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod : WeixinOpen

                User = HttpContext.User,

                ExternalLoginInfo = await _signInManager.GetExternalLoginInfoAsync()
            };
            return View(model);
        }
    }
}
