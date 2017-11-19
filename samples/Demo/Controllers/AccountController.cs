using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using AspNetCore.WeixinOAuth.Demo.Data;

namespace AspNetCore.WeixinOAuth.Demo.Controllers
{
    public class AccountController : BaseController
    {
        private readonly ILogger _logger;

        public AccountController(ILoggerFactory loggerFactory,
            UserManager<AppUser> userManager)
            : base(userManager)
        {
            _logger = loggerFactory.CreateLogger<HomeController>();
        }

        public async Task<IActionResult> Login(string returnUrl = null)
        {
            returnUrl = returnUrl ?? "/";
            var authType = Request.Query["authscheme"];
            // 1.Challenge
            if (!string.IsNullOrEmpty(authType))
            {
                // By default the client will be redirect back to the URL that issued the challenge (/login?authscheme=foo),
                // send them to the home page instead (/).
                await HttpContext.ChallengeAsync(authType, new AuthenticationProperties() { RedirectUri = returnUrl });
                //return RedirectToLocal(returnUrl);
            }

            // 2.Choose an authentication type
            {
                var schemeProvider = HttpContext.RequestServices.GetService(typeof(IAuthenticationSchemeProvider)) as IAuthenticationSchemeProvider;
                var allSchemes = await schemeProvider.GetAllSchemesAsync();
                return View(allSchemes);
            }
        }

        public async Task<IActionResult> Logout()
        {
            // 1.Sign-out to remove the user cookie.
            var name = HttpContext.User.Identity.Name;
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return View(nameof(Logout), name);
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}