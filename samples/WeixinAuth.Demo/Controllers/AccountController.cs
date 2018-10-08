using AspNetCore.Authentication.WeixinAuth;
using AspNetCore.ViewDivert;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WeixinAuth.Demo.Data;
using WeixinAuth.Demo.Models;

namespace WeixinAuth.Demo.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : AppControllerBase
    {
        private readonly SignInManager<AppUser> _signInManager;

        public AccountController(AppDbContext db,
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            ILogger<AccountController> logger)
            : base(db, userManager, logger)
        {
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Login(string returnUrl)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            //如果uncomment下在这段代码，则：在微信公众号内打开那些需要身份验证的页面时，将自动登录。并在ExternalLogin中判断，若未绑定则通常跳转到绑定页面。
            //如果不需要Identity，则可以直接用ExternalLogin中的方法，直接Challenge。
            if (AgentResolver.IsMicroMessenger(HttpContext))
            {
                return ExternalLogin(WeixinAuthDefaults.AuthenticationScheme, returnUrl);
            }

            var vm = new LoginViewModel();
            vm.ReturnUrl = returnUrl;
            return View(vm);
        }

        [HttpPost, ActionName(nameof(Login))]
        public async Task<IActionResult> Login_Post(LoginViewModel vm)
        {
            if (!ModelState.IsValid)
            {
                return View(vm);
            }

            vm.PhoneNumberOrEmailOrUserName = vm.PhoneNumberOrEmailOrUserName.Trim();
            if (string.IsNullOrWhiteSpace(vm.PhoneNumberOrEmailOrUserName))
            {
                AddError("登录帐号不能为空。");
                return View(vm);
            }

            var accountType = "";
            var user = await _userManager.FindByPhoneNumberAsync(vm.PhoneNumberOrEmailOrUserName);
            if (user != null)
            {
                accountType = "PhoneNumber";
            }
            else
            {
                user = await _userManager.FindByEmailAsync(vm.PhoneNumberOrEmailOrUserName);
                if (user != null)
                {
                    accountType = "Email";
                }
                else
                {
                    user = await _userManager.FindByNameAsync(vm.PhoneNumberOrEmailOrUserName);
                    if (user != null)
                    {
                        accountType = "UserName";
                    }
                }
            }

            if (user == null)
            {
                AddError("登录帐号不存在。");
                return View(vm);
            }

            if (accountType == "PhoneNumber"
                && !await _userManager.IsPhoneNumberConfirmedAsync(user))
            {
                AddError("您的手机号码尚未完成验证。您可以使用[忘记密码]功能设置您的密码，或选择其他方式登录。");
                return View(vm);
            }
            if (accountType == "Email"
                && !await _userManager.IsEmailConfirmedAsync(user))
            {
                AddError("您的邮箱地址尚未完成验证。您可以使用[忘记密码]功能设置您的密码，或选择其他方式登录。");
                return View(vm);
            }

            var result = await _signInManager.PasswordSignInAsync(user, vm.Password, false, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                _logger.LogInformation(1, $"User {user.UserName} logged in via {vm.PhoneNumberOrEmailOrUserName}.");
                return RedirectToLocal(vm.ReturnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                throw new NotImplementedException();
            }
            if (result.IsLockedOut)
            {
                throw new NotImplementedException();
            }
            if (result.IsNotAllowed)
            {
                _logger.LogWarning(3, $"User {user.UserName} account logging is not allowed.");

                if (!await _userManager.IsPhoneNumberConfirmedAsync(user))
                {
                    var phoneNumber = await _userManager.GetPhoneNumberAsync(user);
                    if (string.IsNullOrEmpty(phoneNumber))
                    {
                        AddError("您尚未登记手机号码，请先登记并验证您的手机号码。");
                    }
                    else
                    {
                        AddError("您的手机号码尚未得到确认。请先验证您的手机号码。");
                    }
                    return View(vm);
                }
            }

            _logger.LogInformation(4, $"Failed to log in {user.UserName} via {vm.PhoneNumberOrEmailOrUserName}.");
            AddError("登录失败。");
            return View(vm);
        }

        [HttpPost, ActionName("LogOff")]
        public async Task<IActionResult> LogOff_Post()
        {
            var userName = User.Identity.Name;

            // clears the users claims stored in a cookie.
            await _signInManager.SignOutAsync();
            _logger.LogInformation(4, "User {userName} logged out.", userName);
            return RedirectToLocal(DefaultReturnUrl);
        }

        public IActionResult AccessDenied(string message, string returnUrl)
        {
            var vm = new ReturnableViewModel<string>();
            vm.Data = message;
            vm.ReturnUrl = returnUrl;
            return View(vm);
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), GetControllerName<AccountController>(), new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallback(string returnUrl, string remoteError)
        {
            if (remoteError != null)
            {
                _logger.LogWarning(15, $"Error from external provider: {remoteError}");
                AddError($"通过第三方登录时发生错误: {remoteError}。");
                return View(nameof(Login), new { returnUrl });
            }

            var userId = _userManager.GetUserId(HttpContext.User);
            var info = await _signInManager.GetExternalLoginInfoAsync(userId);//根据providerKey和xsrfKey生成Principal
            if (info == null)
            {
                _logger.LogWarning(15, "Failed to log in with external provider.");
                AddError($"第三方登录验证失败，这可能是第三方登录服务组件发生故障造成，请联系系统管理员。");
                return View(nameof(Login), new { returnUrl });
            }

            // 根据providerKey找到本地user，并SignIn.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded) //(5)
            {
                _logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }
            else if (result.IsNotAllowed) //(2)PhoneNumber未验证。转到绑定手机页面。
            {
                _logger.LogInformation("Redirect to bind phone number...");

                var userLocal = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                var vmBindPhone = new BindPhoneViewModel();
                vmBindPhone.PhoneNumber = userLocal.PhoneNumber;
                vmBindPhone.UserId = userLocal.Id;
                vmBindPhone.ReturnUrl = returnUrl;
                return View(nameof(BindPhoneViewModel), vmBindPhone);
            }
            else if (result.IsLockedOut) //(3)账号被锁定，显示结果。
            {
                return View("Lockout");
            }
            else if (result.RequiresTwoFactor) //(4)调用时已经bypassTwoFactor了，所以不应当出现这个结果。
            {
                throw new NotSupportedException();
            }
            else //(1)没有关联本地帐户，尝试绑定已有用户
            {
                if (!string.IsNullOrWhiteSpace(userId)) //直接关联到UserId。这种情况在用户已经登录，然后在个人中心绑定第三方验证时发生。
                {
                    throw new NotImplementedException();
                }
                else
                {
                    #region debug output
                    StringBuilder sb = new StringBuilder();
                    sb.Append($".ProviderKey:{info.ProviderKey}.");
                    sb.Append($".Principal.Identity.Name:{info.Principal?.Identity?.Name}.");
                    sb.Append(".AuthenticationTokens:");
                    sb.Append(string.Join(';', info.AuthenticationTokens?.Select(x => x.Name + ":" + x.Value).ToArray()));
                    sb.Append(".Principal.Claims:");
                    sb.Append(string.Join(';', info.Principal?.Claims?.Select(x => x.Type + ":" + x.Value)));
                    _logger.LogDebug(sb.ToString());
                    #endregion

                    var vmBindPhone = new BindPhoneViewModel();
                    vmBindPhone = null;
                    vmBindPhone.UserId = null;
                    vmBindPhone.ReturnUrl = returnUrl;
                    return View(nameof(BindPhoneViewModel), vmBindPhone);
                }
            }
        }
    }
}