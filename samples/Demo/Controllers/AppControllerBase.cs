using Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Demo.Controllers
{
    public abstract class AppControllerBase : Controller
    {
        protected readonly AppDbContext _db;
        protected readonly AppUserManager _userManager;
        protected readonly ILogger _logger;

        protected string DefaultReturnUrl => Url.Action(nameof(HomeController.Index), GetControllerName<HomeController>());

        public AppControllerBase(
            AppDbContext db,
            UserManager<AppUser> userManager,
            ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _userManager = userManager as AppUserManager ?? throw new ArgumentNullException(nameof(userManager));
            _db = db ?? throw new ArgumentNullException(nameof(db));
        }

        [TempData]
        protected string ErrorMessage { get; set; }

        #region Helpers
        protected void AddError(string error)
        {
            ModelState.AddModelError(string.Empty, error);
        }

        protected void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        public static string GetErrorMessage(IdentityResult result, bool includeCode = false)
        {
            var sb = new StringBuilder();
            if (includeCode)
            {
                foreach (var error in result.Errors)
                {
                    sb.Append($"[{error.Code}]{error.Description}{Environment.NewLine}");
                }
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    sb.Append($"{error.Description}{Environment.NewLine}");
                }
            }
            return sb.ToString();
        }

        protected Task<AppUser> GetCurrentUserAsync()
        {
            return _userManager.GetUserAsync(HttpContext.User);
        }


        protected IActionResult RedirectToLocal(string returnUrl = null)
        {
            if (string.IsNullOrEmpty(returnUrl))
            {
                //returnUrl = Url.Action();
                returnUrl = DefaultReturnUrl;
            }
            //else if (!Url.IsLocalUrl(returnUrl))
            //{
            //    returnUrl = DefaultReturnUrl;
            //}

            return Redirect(returnUrl);
        }

        public static string GetControllerName<TController>()
        {
            var typeName = typeof(TController).Name;
            if (typeName.EndsWith("Controller"))
            {
                return typeName.Substring(0, typeName.Length - "Controller".Length);
            }

            throw new NotSupportedException("This method can only extract a controller name.");
        }
        #endregion
    }

}
