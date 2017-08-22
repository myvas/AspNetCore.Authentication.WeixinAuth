using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNetCore.WeixinOAuth;

namespace Myvas.AspNetCore.Authentication.WeixinOAuth.Sample
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCookie(options =>
                {
                    options.LoginPath = new PathString("/login");
                })
                .AddOAuth("OAuth-weixin", "Weixin", options =>
                 {
                     options.ClientId = Configuration["weixin:appid"];
                     options.ClientSecret = Configuration["weixin:appsecret"];
                     options.AuthorizationEndpoint = "https://open.weixin.qq.com/connect/oauth2/authorize";
                     options.TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
                     options.UserInformationEndpoint = "https://api.weixin.qq.com/sns/userinfo";
                     options.CallbackPath = new PathString("/signin-weixin");
                     options.Events = new OAuthEvents()
                     {
                         OnRemoteFailure = context =>
                         {
                             context.Response.Redirect("/error?FailureMessage=" + UrlEncoder.Default.Encode(context.Failure.Message));
                             context.HandleResponse();
                             return Task.FromResult(0);
                         },
                         OnRedirectToAuthorizationEndpoint = context =>
                           {
                               var requestUri = context.RedirectUri;
                               requestUri.Replace("client_id", "appid");
                               context.RedirectUri = requestUri;
                               
                               context.Response.Redirect(context.RedirectUri);
                               return Task.FromResult(0);
                           },
                         OnCreatingTicket = async context =>
                         {
                             // Get the GitHub user
                             var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                             request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                             request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                             var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                             response.EnsureSuccessStatusCode();

                             var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                             context.RunClaimActions(user);
                         }
                     };
                 })
                .AddOAuth("OAuth-LinkedIn", "LinkedIn", options =>
                  {
                      options.ClientId = Configuration["linkedin:appid"];
                      options.ClientSecret = Configuration["linkedin:appsecret"];
                      options.AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization";
                      options.TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
                      options.UserInformationEndpoint = "https://api.linkedin.com/v1/people/~:(id,formatted-name,email-address,picture-url)";
                      options.Scope.Add("r_basicprofile");
                      options.Scope.Add("r_emailaddress");
                      options.CallbackPath = new PathString("/signin-linkedin");
                  })
                  .AddWeixinOAuth(options=> {
                      options.ClientId = Configuration["weixin:appid"];
                      options.ClientSecret = Configuration["weixin:appsecret"];
                  });

            //var appId = Configuration["weixin:appid"];
            //var appSecret = Configuration["weixin:appsecret"];
            //bool useAdvancedScope = false;
            //try { useAdvancedScope = Convert.ToBoolean(Configuration["weixin:useadvancedscope"]); } catch { }
            //bool useQrcode = false;
            //try { useQrcode = Convert.ToBoolean(Configuration["weixin:useqrcode"]); } catch { }
            //app.UseWeixinOAuth(options =>
            //{
            //    options.AppId = appId;
            //    options.AppSecret = appSecret;
            //    options.Scope.Add(WeixinOAuthScopes.snsapi_userinfo);
            //    options.SaveTokens = true;
            //    //AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpointQrcode,
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();

            // Choose an authentication type
            app.Map("/login", signoutApp =>
            {
                signoutApp.Run(async context =>
                {
                    var authType = context.Request.Query["authscheme"];
                    if (!string.IsNullOrEmpty(authType))
                    {
                        // By default the client will be redirect back to the URL that issued the challenge (/login?authtype=foo),
                        // send them to the home page instead (/).
                        await context.ChallengeAsync(authType, new AuthenticationProperties() { RedirectUri = "/" });
                        return;
                    }

                    context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("Choose an authentication scheme: <br>");
                    var schemeProvider = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
                    foreach (var type in await schemeProvider.GetAllSchemesAsync())
                    {
                        await context.Response.WriteAsync("<a href=\"?authscheme=" + type.Name + "\">" + (type.DisplayName ?? "(suppressed)") + "</a><br>");
                    }
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            // Sign-out to remove the user cookie.
            app.Map("/logout", signoutApp =>
            {
                signoutApp.Run(async context =>
                {
                    context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("You have been logged out. Goodbye " + context.User.Identity.Name + "<br>");
                    await context.Response.WriteAsync("<a href=\"/\">Home</a>");
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            // Display the remote error
            app.Map("/error", errorApp =>
            {
                errorApp.Run(async context =>
                {
                    context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("An remote failure has occurred: " + context.Request.Query["FailureMessage"] + "<br>");
                    await context.Response.WriteAsync("<a href=\"/\">Home</a>");
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            app.Run(async context =>
                 {
                     // CookieAuthenticationOptions.AutomaticAuthenticate = true (default) causes User to be set
                     var user = context.User;

                     // This is what [Authorize] calls
                     // var user = await context.Authentication.AuthenticateAsync(AuthenticationManager.AutomaticScheme);

                     // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                     // var user = await context.Authentication.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                     // Deny anonymous request beyond this point.
                     if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                     {
                         // This is what [Authorize] calls
                         // The cookie middleware will intercept this 401 and redirect to /login
                         await context.ChallengeAsync();

                         // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                         // await context.Authentication.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                         return;
                     }

                     // Display user information
                     context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                     await context.Response.WriteAsync("<html><body>");
                     await context.Response.WriteAsync("Hello " + (context.User.Identity.Name ?? "anonymous") + "<br>");
                     foreach (var claim in context.User.Claims)
                     {
                         await context.Response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
                     }

                     await context.Response.WriteAsync("Tokens:<br>");

                     await context.Response.WriteAsync("Access Token: " + await context.GetTokenAsync("access_token") + "<br>");
                     await context.Response.WriteAsync("Refresh Token: " + await context.GetTokenAsync("refresh_token") + "<br>");
                     await context.Response.WriteAsync("Token Type: " + await context.GetTokenAsync("token_type") + "<br>");
                     await context.Response.WriteAsync("expires_at: " + await context.GetTokenAsync("expires_at") + "<br>");
                     await context.Response.WriteAsync("<a href=\"/api/anonymousvisitor\">Anonymous Visitor</a><br>");
                     await context.Response.WriteAsync("<a href=\"/api/authorizedvisitor\">Authorized Visitor</a><br>");
                     await context.Response.WriteAsync("<a href=\"/logout\">Logout</a><br>");
                     await context.Response.WriteAsync("</body></html>");
                 });
        }
    }
}