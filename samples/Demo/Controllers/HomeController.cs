using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication;
using AspNetCore.WeixinOAuth.Demo.Models;
using AspNetCore.WeixinOAuth.Demo.Data;
using Microsoft.AspNetCore.Authorization;

namespace AspNetCore.WeixinOAuth.Demo.Controllers
{
    public class HomeController : BaseController
    {
        private readonly ILogger _logger;

        public HomeController(ILoggerFactory loggerFactory,
            UserManager<AppUser> userManager)
            : base(userManager)
        {
            _logger = loggerFactory.CreateLogger<HomeController>();
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> UserInfo()
        {
            var model = new UserInfoModel()
            {
                IsAuthenticated = HttpContext.User.Identity.IsAuthenticated,
                UserName = HttpContext.User.Identity.Name,
                Claims = HttpContext.User.Claims,
                AccessToken = await HttpContext.GetTokenAsync("access_token"),
                RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
                ExpiresAt = await HttpContext.GetTokenAsync("expires_at"),
                TokenType = await HttpContext.GetTokenAsync("token_type"),
            };
            return View(model);
        }
        
        public IActionResult Error()
        {
            // 1.Display the remote error
            var feature = HttpContext.Features.Get<IExceptionHandlerFeature>();
            var error = feature?.Error;

            if (error != null)
            {
                _logger.LogError(error.Message, error);
            }

            return View(error);
        }

    }
}