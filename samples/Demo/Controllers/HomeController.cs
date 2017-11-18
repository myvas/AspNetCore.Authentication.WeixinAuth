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

        public async Task<IActionResult> X(HomeModel model)
        { 
            // CookieAuthenticationOptions.AutomaticAuthenticate = true (default) causes User to be set
            var user = HttpContext.User;

            // This is what [Authorize] calls
            // var user = await HttpContext.AuthenticateAsync(AuthenticationManager.AutomaticScheme);

            // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
            // var user = await HttpContext.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

            // Deny anonymous request beyond this point.
            if (user == null)// || !user.Identities.Any(identity => identity.IsAuthenticated))
            {
                // This is what [Authorize] calls
                // The cookie middleware will intercept this 401 and redirect to /Account/Login
                await HttpContext.ChallengeAsync();

                // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                // await HttpContext.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                return View(model ?? new HomeModel());
            }
            else
            {
                // Display user information
                //var 
                model = new HomeModel()
                {
                    UserName = HttpContext.User.Identity.Name,
                    Claims = HttpContext.User.Claims,
                    AccessToken = await HttpContext.GetTokenAsync("access_token"),
                    RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
                    ExpiresAt = await HttpContext.GetTokenAsync("expires_at"),
                    TokenType = await HttpContext.GetTokenAsync("token_type"),
                };
                return View(model);
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> UserId()
        {
            AppUser user = await _userManager.GetUserAsync(HttpContext.User);
            return View(user?.Id);
        }

        [Authorize]
        public async Task<IActionResult> UserInfo()
        {
            var model = new HomeModel()
            {
                UserName = HttpContext.User.Identity.Name,
                Claims = HttpContext.User.Claims,
                AccessToken = await HttpContext.GetTokenAsync("access_token"),
                RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
                ExpiresAt = await HttpContext.GetTokenAsync("expires_at"),
                TokenType = await HttpContext.GetTokenAsync("token_type"),
            };
            return View(model);
        }

        public IActionResult About()
        {
            return View();
        }

        public IActionResult Contact()
        {
            return View();
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