using AspNetCore.QcloudSms;
using AspNetCore.ViewDivertMiddleware;
using AspNetCore.WeixinOAuth;
using Demo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Demo.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : AppControllerBase
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ISmsSender _smsSender;

        public AccountController(AppDbContext db,
            ISmsSender smsSender,
            SignInManager<AppUser> signInManager,
            UserManager<AppUser> userManager,
            ILogger<AccountController> logger)
            : base(db, userManager, logger)
        {
            _smsSender = smsSender ?? throw new ArgumentNullException(nameof(smsSender));
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        }

        public async Task<IActionResult> Login(string returnUrl)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            if (AgentResolver.IsMicroMessenger(HttpContext))
            {
                return ExternalLogin(WeixinOAuthDefaults.AuthenticationScheme, returnUrl);
            }

            var vm = new LoginViewModel();
            vm.ReturnUrl = returnUrl;
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel vm)
        {
            var rememberMe = true;
            if (!ModelState.IsValid)
            {
                // If we got this far, something failed, redisplay form
                return View(vm);
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, set lockoutOnFailure: true
            var result = await _signInManager.PasswordSignInAsync(vm.PhoneNumber, vm.Password, rememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");
                return RedirectToLocal(vm.ReturnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                throw new NotSupportedException();
            }
            if (result.IsLockedOut)
            {
                throw new NotImplementedException();
            }
            if (result.IsNotAllowed)
            {
                throw new NotImplementedException();
            }
            else
            {
                AddError("Invalid login attempt.");
                return View(vm);
            }
        }

        public IActionResult Register(string returnUrl)
        {
            var vm = new RegisterViewModel();
            vm.ReturnUrl = returnUrl;
            return View(vm);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel vm)
        {
            if (ModelState.IsValid)
            {
                var user = new AppUser { UserName = ShortGuid.NewGuid().ToString(), PhoneNumber = vm.PhoneNumber };
                var result = await _userManager.CreateAsync(user, vm.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, vm.PhoneNumber);
                    await _smsSender.SendSmsAsync(vm.PhoneNumber, code);

                    var vmRegisterVerifyCode = new RegisterVerifyCodeViewModel();
                    vmRegisterVerifyCode.ReturnUrl = Url.Action(nameof(RegisteredConfirmation), GetControllerName<AccountController>(), new { vm.ReturnUrl });
                    vmRegisterVerifyCode.UserId = user.Id;
                    vmRegisterVerifyCode.PhoneNumber = vm.PhoneNumber;
                    return View(nameof(RegisterVerifyCode), vmRegisterVerifyCode);
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(vm);
        }
        
        [HttpPost]
        public async Task<IActionResult> RegisterVerifyCode (RegisterVerifyCodeViewModel vm)
        {
            if (!ModelState.IsValid)
            {
                return View(vm);
            }

            if (string.IsNullOrEmpty(vm.UserId))
            {
                AddError("该页面已失效！");
                return View(vm);
            }

            var user = await _userManager.FindByIdAsync(vm.UserId);
            var result = await _userManager.VerifyAndConfirmPhoneNumberAsync(user, vm.Code);
            if (!result.Succeeded)
            {
                AddErrors(result);
                return View(vm);
            }

            return RedirectToLocal(vm.ReturnUrl);
        }
        
        public IActionResult RegisteredConfirmation(string returnUrl)
        {
            var vm = new ReturnableViewModel();
            vm.ReturnUrl = returnUrl;
            return View(vm);
        }

        [HttpPost, ActionName("LogOff")]
        public async Task<IActionResult> LogOff_Post()
        {
            await _signInManager.SignOutAsync();

            _logger.LogInformation("User logged out.");
            return RedirectToLocal(DefaultReturnUrl);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            string userId = _userManager.GetUserId(User);

            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), GetControllerName<AccountController>(), new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userId);
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallback(string returnUrl, string remoteError)
        {
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToAction(nameof(Login));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                throw new NotImplementedException();
            }
            if (result.IsNotAllowed)
            {
                throw new NotImplementedException();
            }

            // try to auto bind to one exists user, with openid
            {
                // If the user does not have an account, then ask the user to create an account.
                var phoneNumber = info.Principal.FindFirstValue(ClaimTypes.MobilePhone);
                return View(nameof(ExternalLoginInputPhoneNumber), new ExternalLoginPhoneNumberViewModel
                {
                    LoginProvider = info.LoginProvider,
                    ReturnUrl = returnUrl,
                    PhoneNumber = phoneNumber
                });
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ExternalLoginInputPhoneNumber(ExternalLoginPhoneNumberViewModel model)
        {
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginSendVcode(ExternalLoginPhoneNumberViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                return View("ExternalLoginInputPhoneNumber", model);
            }

            // Get the information about the user from the external login provider
            var (user, code) = await _userManager.GenerateChangePhoneNumberTokenAsync(model.PhoneNumber);
            if (string.IsNullOrEmpty(code))
            {
                throw new ApplicationException($"Error generating code to mobile phone {model.PhoneNumber}.");
            }

            var codeText = $"【新广州入户】{code}为您的验证码。如非本人操作，请忽略本短信。";
            var sendResult = await _smsSender.SendSmsAsync(user.PhoneNumber, codeText);
            if (!sendResult)
            {
                throw new ApplicationException($"Error sending code to mobile phone {user.PhoneNumber} with text: {codeText}.");
            }

            ViewData["ReturnUrl"] = returnUrl;
            ViewData["PhoneNumber"] = user.PhoneNumber;
            return View("ExternalLoginInputCode", new ExternalLoginVcodeViewModel { PhoneNumber = user.PhoneNumber });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginCodeVerification(ExternalLoginVcodeViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                ModelState.AddModelError(string.Empty, "Model state is invalid!");
                return View("ExternalLoginInputCode", model);
            }
            if (string.IsNullOrEmpty(model.PhoneNumber))
            {
                ViewData["ReturnUrl"] = returnUrl;
                ModelState.AddModelError(string.Empty, "phoneNumber can not be empty!");
                return View("ExternalLoginInputCode", model);
            }
            var (user, pass) = await _userManager.VerifyChangePhoneNumberTokenAsync(model.PhoneNumber, model.Code);
            if (user == null || !pass.Succeeded)
            {
                ViewData["ReturnUrl"] = returnUrl;
                ModelState.AddModelError(string.Empty, "Failed on verifying code!");
                return View("ExternalLoginInputCode", model);
            }

            // Get the information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                throw new ApplicationException("Error loading external login information during confirmation.");
            }

            var identityResult = await _userManager.AddLoginAsync(user, info);
            if (identityResult.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }

            AddErrors(identityResult);
            return View("ExternalLoginInputCode", model);
        }
        
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.PhoneNumber);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }

                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                await _smsSender.SendSmsAsync(model.PhoneNumber, code);
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }
        
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
