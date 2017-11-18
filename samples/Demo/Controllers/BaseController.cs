using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Microsoft.AspNetCore.Identity;
using AspNetCore.WeixinOAuth.Demo.Data;

namespace AspNetCore.WeixinOAuth.Demo.Controllers
{
    public abstract class BaseController : Controller
    {
        protected readonly UserManager<AppUser> _userManager;

        public BaseController(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        protected Task<AppUser> GetCurrentUserAsync()
        {
            return _userManager.GetUserAsync(HttpContext.User);
        }

        protected IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), TrimTailOfControllerName(nameof(HomeController)));
            }
        }
        
        protected string TrimTailOfControllerName(string controllerNameWithTail)
        {
            var pos = controllerNameWithTail.LastIndexOf("Controller");
            var len = controllerNameWithTail.Length;
            return controllerNameWithTail.Substring(0, pos);
        }
    }
}