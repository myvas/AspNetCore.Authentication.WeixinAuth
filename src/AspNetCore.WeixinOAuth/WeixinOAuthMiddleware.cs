using System;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.Net.Http;
using Microsoft.AspNetCore.Http.Authentication;
using AspNetCore.WeixinOAuth.Messages;
using AspNetCore.WeixinOAuth.Events;

namespace AspNetCore.WeixinOAuth
{
    /// <summary>
    /// ASP.NET Core middleware for authenticating users using Weixin OAuth.
    /// </summary>
    public class WeixinOAuthMiddleware : AuthenticationMiddleware<WeixinOAuthOptions>
    {
        protected HttpClient Backchannel { get; private set; }

        /// <summary>
        /// Initializes a new <see cref="WeixinOAuthMiddleware" />.
        /// </summary>
        /// <param name="next">The next middleware in the application pipeline to invoke.</param>
        /// <param name="options">Configuration options for the middleware.</param>
        /// <param name="loggerFactory"></param>
        /// <param name="encoder"></param>
        /// <param name="sharedOptions">Configuration options from service.AddAuthentication(options => ...)</param>
        /// <param name="dataProtectionProvider"></param>
        public WeixinOAuthMiddleware(
            RequestDelegate next,
            IOptions<WeixinOAuthOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            IOptions<SharedAuthenticationOptions> sharedOptions,
            IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, encoder)
		{
			if (next == null)
			{
				throw new ArgumentNullException(nameof(next));
			}
			if (dataProtectionProvider == null)
			{
				throw new ArgumentNullException(nameof(dataProtectionProvider));
			}
			if (loggerFactory == null)
			{
				throw new ArgumentNullException(nameof(loggerFactory));
			}
			if (encoder == null)
			{
				throw new ArgumentNullException(nameof(encoder));
            }
            if (sharedOptions == null)
            {
                throw new ArgumentNullException(nameof(sharedOptions));
            }
            if (options == null)
			{
				throw new ArgumentNullException(nameof(options));
			}

            // todo: review error handling
            if (string.IsNullOrEmpty(Options.AuthenticationScheme))
            {
                throw new ArgumentException($"参数 {nameof(Options.AuthenticationScheme)} 不能为空");
            }

            if (string.IsNullOrEmpty(Options.AppId))
            {
                throw new ArgumentException($"参数 {nameof(Options.AppId)} 不能为空");
            }

            if (string.IsNullOrEmpty(Options.AppSecret))
            {
                throw new ArgumentException($"参数 {nameof(Options.AppSecret)} 不能为空");
            }

            if (string.IsNullOrEmpty(Options.AuthorizationEndpoint))
            {
                throw new ArgumentException($"参数 {nameof(Options.AuthorizationEndpoint)} 不能为空");
            }

            if (string.IsNullOrEmpty(Options.TokenEndpoint))
            {
                throw new ArgumentException($"参数 {nameof(Options.TokenEndpoint)} 不能为空");
            }

            if (!Options.CallbackPath.HasValue)
            {
                throw new ArgumentException($"参数 {nameof(Options.CallbackPath)} 不能为空");
            }

            if (Options.Events == null)
            {
                Options.Events = new WeixinOAuthEvents();
            }
            
            if (Options.StateDataFormat == null)
            {
                var dataProtector = dataProtectionProvider.CreateProtector(
                    GetType().FullName, Options.AuthenticationScheme, "v1");
                Options.StateDataFormat = new SecureDataFormat<AuthenticationProperties>(
                    new AuthenticationPropertiesSerializer(),
                    dataProtector);
            }
            
            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                Options.SignInScheme = sharedOptions.Value.SignInScheme;
            }
            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                throw new ArgumentException($"参数 {nameof(Options.SignInScheme)} 不能为空");
            }

            Backchannel = new HttpClient(Options.BackchannelHttpHandler ?? new HttpClientHandler());
            Backchannel.Timeout = Options.BackchannelTimeout;
            Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            Backchannel.DefaultRequestHeaders.Accept.ParseAdd("*/*");
            Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Myvas ASP.NET Core WeixinOAuth middleware");
            Backchannel.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler{TOptions}" /> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler{TOptions}" /> configured with the <see cref="WeixinOAuthOptions" /> supplied to the constructor.</returns>
        protected override AuthenticationHandler<WeixinOAuthOptions> CreateHandler()
		{
			return new WeixinOAuthHandler(Backchannel);
		}
	}
}
