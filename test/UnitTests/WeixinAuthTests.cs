using AspNetCore.Authentication.WeixinAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests
{
    public class WeixinAuthTests
    {
        private void ConfigureDefaults(WeixinAuthOptions o)
        {
            o.AppId = "Test Id";
            o.AppSecret = "Test Secret";
            //o.SignInScheme = "auth1";//WeixinAuthDefaults.AuthenticationScheme;
        }

        [Fact]
        public async Task ChallengeWithRealAccount()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.AppId = "wx02056e2b2b9cc4ef";
                o.AppSecret = "c175a359cd383213906bc3aa346fff2f";
                o.StateDataFormat = stateFormat;
            });

            var transaction = await server.SendAsync("http://weixinoauth.myvas.com/challenge-weixinauth");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            //Location: https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx02056e2b2b9cc4ef&redirect_uri=http%3A%2F%2Fweixinoauth.myvas.com%2Fsignin-weixinauth&response_type=code&scope=snsapi_base,snsapi_userinfo&state=n6TFxuWkbt56BFslzKvkKXi1VgIHkUprbxyLM82mVm8#wechat_redirect
            Assert.StartsWith(WeixinAuthDefaults.AuthorizationEndpoint, transaction.Response.Headers.Location.AbsoluteUri);

            var query = System.Web.HttpUtility.ParseQueryString(transaction.Response.Headers.Location.Query);
            Assert.Equal("wx02056e2b2b9cc4ef", query.Get("appid"));
            Assert.NotEmpty(query.Get("redirect_uri"));
            Assert.Equal("code", query.Get("response_type"));
            Assert.Equal("snsapi_base,snsapi_userinfo", query.Get("scope"));

            var state = query.Get("state");
            Assert.NotEmpty(state);
            Assert.True(state.Length <= 128, $"state length must less than 128, but actual is {state.Length}");
        }

        [Fact]
        public async Task CodeMockValid()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.BackchannelHttpHandler = CreateBackchannel();
                o.Events = new OAuthEvents()
                {
                    OnCreatingTicket = context =>
                    {
                        Assert.NotNull(context.User);
                        Assert.Equal("Test Access Token", context.AccessToken);
                        Assert.Equal("Test Refresh Token", context.RefreshToken);
                        Assert.Equal(TimeSpan.FromSeconds(3600), context.ExpiresIn);
                        Assert.Equal("Test User ID", context.Identity.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                        Assert.Equal("Test Name", context.Identity.FindFirst(ClaimTypes.Name)?.Value);
                        return Task.FromResult(0);
                    }
                };
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/Account/ExternalLoginCallback?returnUrl=%2FHome%2FUserInfo";
            var state = stateFormat.Protect(properties);

            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");

            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/Account/ExternalLoginCallback?returnUrl=%2FHome%2FUserInfo", transaction.Response.Headers.GetValues("Location").First());
        }

        [Fact]
        public async Task CanForwardDefault()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler>("auth1", "auth1");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1";
                o.ForwardDefault = "auth1";
            });

            var forwardDefault = new TestHandler();
            services.AddSingleton(forwardDefault);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);

            await context.AuthenticateAsync();
            Assert.Equal(1, forwardDefault.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, forwardDefault.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, forwardDefault.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));
        }


        [Fact]
        public async Task ForwardSignInThrows()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardSignOut = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));
        }


        [Fact]
        public async Task ForwardSignOutThrows()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardSignOut = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
        }


        [Fact]
        public async Task ForwardForbidWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1"; //Important!
                o.ForwardDefault = "auth1";
                o.ForwardForbid = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.ForbidAsync();
            Assert.Equal(0, specific.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(1, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
        }


        [Fact]
        public async Task ForwardAuthenticateWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1"; //Important!
                o.ForwardDefault = "auth1";
                o.ForwardAuthenticate = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(0, specific.SignOutCount);
            Assert.Equal(1, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
        }

        [Fact]
        public async Task ForwardChallengeWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler>("specific", "specific");
                o.AddScheme<TestHandler2>("auth1", "auth1");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1"; //Important!
                o.ForwardDefault = "auth1";
                o.ForwardChallenge = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.ChallengeAsync();
            Assert.Equal(0, specific.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(1, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
        }

        [Fact]
        public async Task ForwardSelectorWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler3>("selector", "selector");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1"; //Important!
                o.ForwardDefault = "auth1";
                o.ForwardDefaultSelector = _ => "selector";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            var selector = new TestHandler3();
            services.AddSingleton(selector);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(1, selector.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, selector.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, selector.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);
            Assert.Equal(0, specific.SignOutCount);
        }

        [Fact]
        public async Task NullForwardSelectorUsesDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler3>("selector", "selector");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1"; //Important!
                o.ForwardDefault = "auth1";
                o.ForwardDefaultSelector = _ => null;
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            var selector = new TestHandler3();
            services.AddSingleton(selector);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(1, forwardDefault.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, forwardDefault.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, forwardDefault.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));

            Assert.Equal(0, selector.AuthenticateCount);
            Assert.Equal(0, selector.ForbidCount);
            Assert.Equal(0, selector.ChallengeCount);
            Assert.Equal(0, selector.SignInCount);
            Assert.Equal(0, selector.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);
            Assert.Equal(0, specific.SignOutCount);
        }

        [Fact]
        public async Task SpecificForwardWinsOverSelectorAndDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = WeixinAuthDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler3>("selector", "selector");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddWeixinAuth(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = "auth1"; //Important!
                o.ForwardDefault = "auth1";
                o.ForwardDefaultSelector = _ => "selector";
                o.ForwardAuthenticate = "specific";
                o.ForwardChallenge = "specific";
                o.ForwardSignIn = "specific";
                o.ForwardSignOut = "specific";
                o.ForwardForbid = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            var selector = new TestHandler3();
            services.AddSingleton(selector);

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(1, specific.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, specific.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, specific.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
            Assert.Equal(0, selector.AuthenticateCount);
            Assert.Equal(0, selector.ForbidCount);
            Assert.Equal(0, selector.ChallengeCount);
            Assert.Equal(0, selector.SignInCount);
            Assert.Equal(0, selector.SignOutCount);
        }

        [Fact]
        public async Task VerifySignInSchemeCannotBeSetToSelf()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.SignInScheme = WeixinAuthDefaults.AuthenticationScheme;
            });
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => server.SendAsync("https://example.com/challenge"));
            Assert.Contains("cannot be set to itself", error.Message);
        }

        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddWeixinAuth();
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(WeixinAuthDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("WeixinAuthHandler", scheme.HandlerType.Name);
            Assert.Equal(WeixinAuthDefaults.AuthenticationScheme, scheme.DisplayName);
        }

        [Fact]
        public async Task ChallengeWillTriggerRedirection()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });

            var transaction = await server.SendAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            var location = transaction.Response.Headers.Location.ToString();
            Assert.StartsWith(WeixinAuthDefaults.AuthorizationEndpoint, location);
            Assert.Contains("&redirect_uri=", location);
            Assert.Contains("&response_type=code", location);
            Assert.Contains("&scope=", location);
            Assert.Contains("&state=", location);
            Assert.Contains("#wechat_redirect", location);

            Assert.DoesNotContain("access_type=", location);
            Assert.DoesNotContain("prompt=", location);
            Assert.DoesNotContain("approval_prompt=", location);
            Assert.DoesNotContain("login_hint=", location);
            Assert.DoesNotContain("include_granted_scopes=", location);
        }

        [Fact]
        public async Task SignInThrows()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var transaction = await server.SendAsync("https://example.com/signin");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task SignOutThrows()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var transaction = await server.SendAsync("https://example.com/signout");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ForbidWillRedirect()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var transaction = await server.SendAsync("https://example.com/forbid");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task Challenge401WillNotTriggerRedirection()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var transaction = await server.SendAsync("https://example.com/401");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ChallengeWillSetCorrelationCookie()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var transaction = await server.SendAsync("https://example.com/challenge");
            Assert.Contains(transaction.SetCookie, cookie => cookie.StartsWith(".AspNetCore.Correlation.WeixinAuth."));
        }

        [Fact]
        public async Task ChallengeWillSetDefaultScope()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var transaction = await server.SendAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            var query = transaction.Response.Headers.Location.Query;
            Assert.Contains("scope=", query);
        }

        [Fact]
        public async Task ChallengeWillUseAuthenticationPropertiesParametersAsQueryArguments()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            },
            context =>
            {
                var req = context.Request;
                var res = context.Response;
                if (req.Path == new PathString("/challenge2"))
                {
                    return context.ChallengeAsync("WeixinAuth", new OAuthChallengeProperties
                    {
                        Scope = new string[] { "snsapi_login", "https://www.googleapis.com/auth/plus.login" },
                    });
                }

                return Task.FromResult<object>(null);
            });
            var transaction = await server.SendAsync("https://example.com/challenge2");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);

            // verify query arguments
            var query = QueryHelpers.ParseQuery(transaction.Response.Headers.Location.Query);
            Assert.Equal("snsapi_login,https://www.googleapis.com/auth/plus.login", query["scope"]);
            //Assert.Equal("test@example.com", query["login_hint"]);

            // verify that the passed items were not serialized
            var state = query["state"];
            var stateProperties =  AuthenticationPropertiesExtensions.GetByCorrelationId(stateFormat, transaction.SetCookie, state, WeixinAuthDefaults.AuthenticationScheme, ".AspNetCore.Correlation");
            Assert.DoesNotContain("scope", stateProperties.Items.Keys);
            Assert.DoesNotContain("login_hint", stateProperties.Items.Keys);
        }

        [Fact]
        public async Task ChallengeWillUseAuthenticationPropertiesItemsAsParameters()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            },
            context =>
            {
                var req = context.Request;
                var res = context.Response;
                if (req.Path == new PathString("/challenge2"))
                {
                    return context.ChallengeAsync(WeixinAuthDefaults.AuthenticationScheme, new AuthenticationProperties(new Dictionary<string, string>()
                    {
                        { "scope", "https://www.googleapis.com/auth/plus.login" },
                        //{ "login_hint", "test@example.com" },
                    }));
                }

                return Task.FromResult<object>(null);
            });
            var transaction = await server.SendAsync("https://example.com/challenge2");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);

            // verify query arguments
            var query = QueryHelpers.ParseQuery(transaction.Response.Headers.Location.Query);
            Assert.Equal("https://www.googleapis.com/auth/plus.login", query["scope"]);

            // verify that the passed items were not serialized
            var state = query["state"];
            var stateProperties = AuthenticationPropertiesExtensions.GetByCorrelationId(stateFormat, transaction.SetCookie, state, WeixinAuthDefaults.AuthenticationScheme, ".AspNetCore.Correlation");
            Assert.DoesNotContain("scope", stateProperties.Items.Keys);
        }

        [Fact]
        public async Task ChallengeWillUseAuthenticationPropertiesItemsAsQueryArgumentsButParametersWillOverwrite()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            },
            context =>
            {
                var req = context.Request;
                var res = context.Response;
                if (req.Path == new PathString("/challenge2"))
                {
                    return context.ChallengeAsync("WeixinAuth", new OAuthChallengeProperties() { Scope = new string[] { "https://www.googleapis.com/auth/plus.login" } });
                }

                return Task.FromResult<object>(null);
            });
            var transaction = await server.SendAsync("https://example.com/challenge2");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);

            // verify query arguments
            var query = QueryHelpers.ParseQuery(transaction.Response.Headers.Location.Query);
            Assert.Equal("https://www.googleapis.com/auth/plus.login", query[OAuthChallengeProperties.ScopeKey]);

            // verify that the passed items were not serialized
             var state = query["state"];
            var stateProperties = AuthenticationPropertiesExtensions.GetByCorrelationId(stateFormat, transaction.SetCookie, state, WeixinAuthDefaults.AuthenticationScheme, ".AspNetCore.Correlation");
            Assert.Contains(".redirect", stateProperties.Items.Keys);
            Assert.Contains(".xsrf", stateProperties.Items.Keys);
            Assert.DoesNotContain("scope", stateProperties.Items.Keys);
        }

        [Fact]
        public async Task ChallengeWillTriggerApplyRedirectEvent()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.Events = new OAuthEvents
                {
                    OnRedirectToAuthorizationEndpoint = context =>
                    {
                        var oldUri = new Uri(context.RedirectUri);
                        var queryBuilder = new QueryBuilder()
                        {
                            { "custom", "test" }
                        };
                        var customUrl = o.AuthorizationEndpoint + oldUri.PathAndQuery + queryBuilder + "#wechat_redirect";
                        context.Response.Redirect(customUrl);
                        return Task.FromResult(0);
                    }
                };
            });
            var transaction = await server.SendAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            var query = transaction.Response.Headers.Location.Query;
            Assert.Contains("custom=test", query);
        }

        [Fact]
        public async Task AuthenticateWithoutCookieWillFail()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            },
            async context =>
            {
                var req = context.Request;
                var res = context.Response;
                if (req.Path == new PathString("/auth"))
                {
                    var result = await context.AuthenticateAsync("WeixinAuth");
                    Assert.NotNull(result.Failure);
                }
            });
            var transaction = await server.SendAsync("https://example.com/auth");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ReplyPathWithoutStateQueryStringWillBeRejected()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });
            var error = await Assert.ThrowsAnyAsync<Exception>(() => server.SendAsync("https://example.com/signin-WeixinAuth?code=TestCode"));
            Assert.Equal("The oauth state was missing.", error.GetBaseException().Message);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task ReplyPathWithErrorFails(bool redirect)
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = new TestStateDataFormat();
                o.Events = redirect ? new OAuthEvents()
                {
                    OnRemoteFailure = ctx =>
                    {
                        ctx.Response.Redirect("/error?FailureMessage=" + UrlEncoder.Default.Encode(ctx.Failure.Message));
                        ctx.HandleResponse();
                        return Task.FromResult(0);
                    }
                } : new OAuthEvents();
            });
            var sendTask = server.SendAsync("https://example.com/signin-weixinauth?error=OMG&error_description=SoBad&error_uri=foobar&state=protected_state",
                ".AspNetCore.Correlation.WeixinAuth.corrilationId=N");
            if (redirect)
            {
                var transaction = await sendTask;
                Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
                Assert.Equal("/error?FailureMessage=OMG" + UrlEncoder.Default.Encode(";Description=SoBad;Uri=foobar"), transaction.Response.Headers.GetValues("Location").First());
            }
            else
            {
                var error = await Assert.ThrowsAnyAsync<Exception>(() => sendTask);
                Assert.Equal("OMG;Description=SoBad;Uri=foobar", error.GetBaseException().Message);
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("CustomIssuer")]
        public async Task ReplyPathWillAuthenticateValidAuthorizeCodeAndState(string claimsIssuer)
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.SaveTokens = true;
                o.StateDataFormat = stateFormat;
                if (claimsIssuer != null)
                {
                    o.ClaimsIssuer = claimsIssuer;
                }
                o.BackchannelHttpHandler = CreateBackchannel();
            });

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/me", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);

            var authCookie = transaction.AuthenticationCookieValue;
            transaction = await server.SendAsync("https://example.com/me", authCookie);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            var expectedIssuer = claimsIssuer ?? WeixinAuthDefaults.AuthenticationScheme;
            Assert.Equal("Test Name", transaction.FindClaimValue(ClaimTypes.Name, expectedIssuer));
            Assert.Equal("Test User ID", transaction.FindClaimValue(ClaimTypes.NameIdentifier, expectedIssuer));

            // Ensure claims transformation
            Assert.Equal("yup", transaction.FindClaimValue("xform"));

            transaction = await server.SendAsync("https://example.com/tokens", authCookie);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.Equal("Test Access Token", transaction.FindTokenValue("access_token"));
            //Assert.Equal("Bearer", transaction.FindTokenValue("token_type"));
            Assert.NotNull(transaction.FindTokenValue("expires_at"));
        }

        // REVIEW: Fix this once we revisit error handling to not blow up
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task ReplyPathWillThrowIfCodeIsInvalid(bool redirect)
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.BackchannelHttpHandler = new TestHttpMessageHandler
                {
                    Sender = req =>
                    {
                        return ReturnJsonResponse(new { Error = "Error" },
                            HttpStatusCode.BadRequest);
                    }
                };
                o.Events = redirect ? new OAuthEvents()
                {
                    OnRemoteFailure = ctx =>
                    {
                        ctx.Response.Redirect("/error?FailureMessage=" + UrlEncoder.Default.Encode(ctx.Failure.Message));
                        ctx.HandleResponse();
                        return Task.FromResult(0);
                    }
                } : new OAuthEvents();
            });
            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";

            var state = stateFormat.Protect(properties);
            var sendTask = server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            if (redirect)
            {
                var transaction = await sendTask;
                Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
                Assert.Equal("/error?FailureMessage=" + UrlEncoder.Default.Encode("OAuth token endpoint failure: Status: BadRequest;Headers: ;Body: {\"Error\":\"Error\"};"),
                    transaction.Response.Headers.GetValues("Location").First());
            }
            else
            {
                var error = await Assert.ThrowsAnyAsync<Exception>(() => sendTask);
                Assert.Equal("OAuth token endpoint failure: Status: BadRequest;Headers: ;Body: {\"Error\":\"Error\"};",
                    error.GetBaseException().Message);
            }
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task ReplyPathWillRejectIfAccessTokenIsMissing(bool redirect)
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.BackchannelHttpHandler = new TestHttpMessageHandler
                {
                    Sender = req =>
                    {
                        return ReturnJsonResponse(new object());
                    }
                };
                o.Events = redirect ? new OAuthEvents()
                {
                    OnRemoteFailure = ctx =>
                    {
                        ctx.Response.Redirect("/error?FailureMessage=" + UrlEncoder.Default.Encode(ctx.Failure.Message));
                        ctx.HandleResponse();
                        return Task.FromResult(0);
                    }
                } : new OAuthEvents();
            });
            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationValue = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationValue);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var sendTask = server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationValue)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}.{correlationMarker}={state}");
            if (redirect)
            {
                var transaction = await sendTask;
                Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
                Assert.Equal("/error?FailureMessage=" + UrlEncoder.Default.Encode("Failed to retrieve access token."),
                    transaction.Response.Headers.GetValues("Location").First());
            }
            else
            {
                var error = await Assert.ThrowsAnyAsync<Exception>(() => sendTask);
                Assert.Equal("Failed to retrieve access token.", error.GetBaseException().Message);
            }
        }

        [Fact]
        public async Task AuthenticatedEventCanGetRefreshToken()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.BackchannelHttpHandler = CreateBackchannel();
                o.Events = new OAuthEvents
                {
                    OnCreatingTicket = context =>
                    {
                        var refreshToken = context.RefreshToken;
                        context.Principal.AddIdentity(new ClaimsIdentity(new Claim[] { new Claim("RefreshToken", refreshToken, ClaimValueTypes.String, "WeixinAuth") }, "WeixinAuth"));
                        return Task.FromResult(0);
                    }
                };
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/me", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);

            var authCookie = transaction.AuthenticationCookieValue;
            transaction = await server.SendAsync("https://example.com/me", authCookie);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.Equal("Test Refresh Token", transaction.FindClaimValue("RefreshToken"));
        }

        [Fact]
        public async Task NullRedirectUriWillRedirectToSlash()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.BackchannelHttpHandler = CreateBackchannel();
                o.Events = new OAuthEvents
                {
                    OnTicketReceived = context =>
                    {
                        context.Properties.RedirectUri = null;
                        return Task.FromResult(0);
                    }
                };
            });

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationValue = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationValue);
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationValue)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}.{correlationMarker}={state}");

            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);
        }

        [Fact]
        public async Task ValidateAuthenticatedContext()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                //o.AccessType = "offline";
                o.Events = new OAuthEvents()
                {
                    OnCreatingTicket = context =>
                    {
                        Assert.NotNull(context.User);
                        Assert.Equal("Test Access Token", context.AccessToken);
                        Assert.Equal("Test Refresh Token", context.RefreshToken);
                        Assert.Equal(TimeSpan.FromSeconds(3600), context.ExpiresIn);
                        Assert.Equal("Test User ID", context.Identity.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                        Assert.Equal("Test Name", context.Identity.FindFirst(ClaimTypes.Name)?.Value);
                        Assert.Equal("Test Open ID", context.Identity.FindFirst(WeixinAuthClaimTypes.OpenId)?.Value);
                        return Task.FromResult(0);
                    }
                };
                o.BackchannelHttpHandler = CreateBackchannel();
            });

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationValue = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationValue);
            properties.RedirectUri = "/foo";
            var state = stateFormat.Protect(properties);

            //Post a message to the WeixinAuth middleware
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationValue)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/foo", transaction.Response.Headers.GetValues("Location").First());
        }

        [Fact]
        public async Task NoStateCausesException()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });

            //Post a message to the WeixinAuth middleware
            var error = await Assert.ThrowsAnyAsync<Exception>(() => server.SendAsync("https://example.com/signin-WeixinAuth"));
            Assert.Equal("The oauth state was missing.", error.GetBaseException().Message);
        }

        [Fact]
        public async Task StateDataFormatCauseException()
        {
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
            });

            //Post a message to the WeixinAuth middleware
            var error = await Assert.ThrowsAnyAsync<Exception>(() => server.SendAsync("https://example.com/signin-WeixinAuth?state=TestState"));
            Assert.StartsWith("The oauth state cookie was missing", error.GetBaseException().Message);
        }

        [Fact]
        public async Task StateCorrelationMissingCauseException()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            });

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationValue = "TestCorrelationId";
            properties.Items.Add(correlationKey, correlationValue);
            var state = stateFormat.Protect(properties);

            var error3 = await Assert.ThrowsAnyAsync<Exception>(()
                => server.SendAsync(
                    "https://example.com/signin-WeixinAuth?state=" + UrlEncoder.Default.Encode(state)));
            Assert.StartsWith("The oauth state cookie was missing: ", error3.GetBaseException().Message);
        }

        [Fact]
        public async Task StateCorrelationMarkerWrongCauseException()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            });

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationValue = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationValue);
            var state = stateFormat.Protect(properties);

            var error = await Assert.ThrowsAnyAsync<Exception>(()
                => server.SendAsync(
                    $"https://example.com/signin-WeixinAuth?state={UrlEncoder.Default.Encode(correlationValue)}",
                    $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}=HERE_MUST_BE_N"
                    + $";.AspNetCore.Correlation.{ WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}.{correlationMarker}={state}"));
            Assert.Equal("Correlation failed.", error.GetBaseException().Message);
        }

        [Fact]
        public async Task StateCorrelationSuccessCodeMissing()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            });

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationValue = "TestCorrelationId";
            properties.Items.Add(correlationKey, correlationValue);
            var state = stateFormat.Protect(properties);

            var error2 = await Assert.ThrowsAnyAsync<Exception>(()
                => server.SendAsync(
                    "https://example.com/signin-WeixinAuth?state=" + UrlEncoder.Default.Encode(correlationValue),
                    $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}=N"
                    + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationValue}.N={state}"));
            Assert.Equal("Code was not found.", error2.GetBaseException().Message);
        }

        [Fact]
        public async Task CodeInvalidCauseException()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);

            var result = await Assert.ThrowsAnyAsync<Exception>(() => server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}"));

            Assert.StartsWith("OAuth token endpoint failure: ", result.GetBaseException().Message);
            Assert.Contains("invalid appid", result.GetBaseException().Message);
        }

        [Fact]
        public async Task CanRedirectOnError()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.Events = new OAuthEvents()
                {
                    OnRemoteFailure = ctx =>
                    {
                        ctx.Response.Redirect("/error?FailureMessage=" + UrlEncoder.Default.Encode(ctx.Failure.Message));
                        ctx.HandleResponse();
                        return Task.FromResult(0);
                    }
                };
            });

            //Post a message to the WeixinAuth middleware
            var transaction = await server.SendAsync(
                "https://example.com/signin-WeixinAuth?code=TestCode");

            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/error?FailureMessage=" + UrlEncoder.Default.Encode("The oauth state was missing."),
                transaction.Response.Headers.GetValues("Location").First());
        }

        [Fact]
        public async Task AuthenticateAutomaticWhenAlreadySignedInSucceeds()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.SaveTokens = true;
                o.BackchannelHttpHandler = CreateBackchannel();
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/me", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);

            var authCookie = transaction.AuthenticationCookieValue;
            transaction = await server.SendAsync("https://example.com/authenticate", authCookie);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.Equal("Test Name", transaction.FindClaimValue(ClaimTypes.Name));
            Assert.Equal("Test User ID", transaction.FindClaimValue(ClaimTypes.NameIdentifier));

            // Ensure claims transformation
            Assert.Equal("yup", transaction.FindClaimValue("xform"));
        }

        [Fact]
        public async Task AuthenticateWeixinAuthWhenAlreadySignedInSucceeds()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.SaveTokens = true;
                o.BackchannelHttpHandler = CreateBackchannel();
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/me", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);

            var authCookie = transaction.AuthenticationCookieValue;
            transaction = await server.SendAsync("https://example.com/authenticate-WeixinAuth", authCookie);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.Equal("Test Name", transaction.FindClaimValue(ClaimTypes.Name));
            Assert.Equal("Test User ID", transaction.FindClaimValue(ClaimTypes.NameIdentifier));

            // Ensure claims transformation
            Assert.Equal("yup", transaction.FindClaimValue("xform"));
        }

        [Fact]
        public async Task AuthenticateFacebookWhenAlreadySignedWithWeixinAuthReturnsNull()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.SaveTokens = true;
                o.BackchannelHttpHandler = CreateBackchannel();
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/me", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);

            var authCookie = transaction.AuthenticationCookieValue;
            transaction = await server.SendAsync("https://example.com/authenticate-facebook", authCookie);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.Null(transaction.FindClaimValue(ClaimTypes.Name));
        }

        [Fact]
        public async Task ChallengeFacebookWhenAlreadySignedWithWeixinAuthSucceeds()
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var server = CreateServer(o =>
            {
                ConfigureDefaults(o);
                o.StateDataFormat = stateFormat;
                o.SaveTokens = true;
                o.BackchannelHttpHandler = CreateBackchannel();
            });

            // Skip the challenge step, go directly to the callback path

            var properties = new AuthenticationProperties();
            var correlationKey = ".xsrf";
            var correlationId = "TestCorrelationId";
            var correlationMarker = "N";
            properties.Items.Add(correlationKey, correlationId);
            properties.RedirectUri = "/me";
            var state = stateFormat.Protect(properties);
            var transaction = await server.SendAsync(
                $"https://example.com/signin-{WeixinAuthDefaults.AuthenticationScheme}?code=TestCode&state={UrlEncoder.Default.Encode(correlationId)}",
                $".AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}={correlationMarker}"
                + $";.AspNetCore.Correlation.{WeixinAuthDefaults.AuthenticationScheme}.{correlationId}.{correlationMarker}={state}");
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.Equal("/me", transaction.Response.Headers.GetValues("Location").First());
            Assert.True(transaction.SetCookie.Count >= 2);

            var authCookie = transaction.AuthenticationCookieValue;
            transaction = await server.SendAsync("https://example.com/challenge-facebook", authCookie);
            Assert.Equal(HttpStatusCode.Redirect, transaction.Response.StatusCode);
            Assert.StartsWith("https://www.facebook.com/", transaction.Response.Headers.Location.OriginalString);
        }

        private HttpMessageHandler CreateBackchannel()
        {
            return new TestHttpMessageHandler()
            {
                Sender = req =>
                {
                    if (req.RequestUri.AbsoluteUri.StartsWith(WeixinAuthDefaults.TokenEndpoint))
                    {
                        return ReturnJsonResponse(new
                        {
                            access_token = "Test Access Token",
                            expires_in = 3600,
                            refresh_token = "Test Refresh Token",
                            openid = "Test Open ID",
                            scope = "Test_Scope,snsapi_userinfo",
                            unionid = "Test User ID"
                            //token_type = "Bearer"
                        });
                    }
                    else if (req.RequestUri.AbsoluteUri.StartsWith(WeixinAuthDefaults.UserInformationEndpoint))
                    {
                        return ReturnJsonResponse(new
                        {
                            openid = "Test Open ID",
                            nickname = "Test Name",
                            sex = 1,
                            province = "Test Province",
                            city = "Test City",
                            country = "Test Country",
                            headimgurl = "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0",
                            privilege = new[]
                                {
                                    "PRIVILEGE1",
                                    "PRIVILEGE2"
                                },
                            unionid = "Test User ID"
                        });
                    }

                    throw new NotImplementedException(req.RequestUri.AbsoluteUri);
                }
            };
        }

        private static HttpResponseMessage ReturnJsonResponse(object content, HttpStatusCode code = HttpStatusCode.OK)
        {
            var res = new HttpResponseMessage(code);
            var text = JsonConvert.SerializeObject(content);
            res.Content = new StringContent(text, Encoding.UTF8, "application/json");
            return res;
        }

        private class ClaimsTransformer : IClaimsTransformation
        {
            public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal p)
            {
                if (!p.Identities.Any(i => i.AuthenticationType == "xform"))
                {
                    var id = new ClaimsIdentity("xform");
                    id.AddClaim(new Claim("xform", "yup"));
                    p.AddIdentity(id);
                }
                return Task.FromResult(p);
            }
        }

        private static TestServer CreateServer(Action<WeixinAuthOptions> configureOptions, Func<HttpContext, Task> testpath = null)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();
                    app.Use(async (context, next) =>
                    {
                        var req = context.Request;
                        var res = context.Response;
                        if (req.Path == new PathString("/challenge"))
                        {
                            await context.ChallengeAsync();
                        }
                        else if (req.Path == new PathString("/challenge-facebook"))
                        {
                            await context.ChallengeAsync(FacebookDefaults.AuthenticationScheme);
                        }
                        else if (req.Path == new PathString("/challenge-WeixinAuth"))
                        {
                            var provider = WeixinAuthDefaults.AuthenticationScheme;
                            string userId = "1234567890123456789012";
                            // Request a redirect to the external login provider.
                            var redirectUrl = "/Account/ExternalLoginCallback?returnUrl=%2FHome%2FUserInfo";
                            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
                            properties.Items["LoginProvider"] = provider;
                            if (userId != null)
                            {
                                properties.Items["XsrfId"] = userId;
                            }
                            await context.ChallengeAsync(WeixinAuthDefaults.AuthenticationScheme, properties);
                        }
                        else if (req.Path == new PathString("/tokens"))
                        {
                            var result = await context.AuthenticateAsync(TestExtensions.CookieAuthenticationScheme);
                            var tokens = result.Properties.GetTokens();
                            res.Describe(tokens);
                        }
                        else if (req.Path == new PathString("/me"))
                        {
                            res.Describe(context.User);
                        }
                        else if (req.Path == new PathString("/authenticate"))
                        {
                            var result = await context.AuthenticateAsync(TestExtensions.CookieAuthenticationScheme);
                            res.Describe(result.Principal);
                        }
                        else if (req.Path == new PathString("/authenticate-WeixinAuth"))
                        {
                            var result = await context.AuthenticateAsync(WeixinAuthDefaults.AuthenticationScheme);
                            res.Describe(result?.Principal);
                        }
                        else if (req.Path == new PathString("/authenticate-facebook"))
                        {
                            var result = await context.AuthenticateAsync(FacebookDefaults.AuthenticationScheme);
                            res.Describe(result?.Principal);
                        }
                        else if (req.Path == new PathString("/401"))
                        {
                            res.StatusCode = (int)HttpStatusCode.Unauthorized;// 401;
                        }
                        else if (req.Path == new PathString("/unauthorized"))
                        {
                            // Simulate Authorization failure
                            var result = await context.AuthenticateAsync(WeixinAuthDefaults.AuthenticationScheme);
                            await context.ChallengeAsync(WeixinAuthDefaults.AuthenticationScheme);
                        }
                        else if (req.Path == new PathString("/unauthorized-auto"))
                        {
                            var result = await context.AuthenticateAsync(WeixinAuthDefaults.AuthenticationScheme);
                            await context.ChallengeAsync(WeixinAuthDefaults.AuthenticationScheme);
                        }
                        else if (req.Path == new PathString("/signin"))
                        {
                            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(WeixinAuthDefaults.AuthenticationScheme, new ClaimsPrincipal()));
                        }
                        else if (req.Path == new PathString("/signout"))
                        {
                            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync(WeixinAuthDefaults.AuthenticationScheme));
                        }
                        else if (req.Path == new PathString("/forbid"))
                        {
                            await context.ForbidAsync(WeixinAuthDefaults.AuthenticationScheme);
                        }
                        else if (testpath != null)
                        {
                            await testpath(context);
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
                .ConfigureServices(services =>
                {
                    services.AddTransient<IClaimsTransformation, ClaimsTransformer>();
                    services.AddAuthentication(TestExtensions.CookieAuthenticationScheme)
                        .AddCookie(TestExtensions.CookieAuthenticationScheme, o => o.ForwardChallenge = WeixinAuthDefaults.AuthenticationScheme)
                        .AddWeixinAuth(configureOptions)
                        .AddFacebook(o =>
                        {
                            o.ClientId = "Test Facebook ClientId";
                            o.ClientSecret = "Test Facebook AppSecrent";
                        });
                });
            return new TestServer(builder);
        }

        private class TestStateDataFormat : ISecureDataFormat<AuthenticationProperties>
        {
            private AuthenticationProperties Data { get; set; }

            public string Protect(AuthenticationProperties data)
            {
                return "protected_state";
            }

            public string Protect(AuthenticationProperties data, string purpose)
            {
                throw new NotImplementedException();
            }

            public AuthenticationProperties Unprotect(string protectedText)
            {
                Assert.Equal("protected_state", protectedText);
                var properties = new AuthenticationProperties(new Dictionary<string, string>()
                {
                    { ".xsrf", "corrilationId" },
                    { "testkey", "testvalue" }
                });
                properties.RedirectUri = "http://testhost/redirect";
                return properties;
            }

            public AuthenticationProperties Unprotect(string protectedText, string purpose)
            {
                throw new NotImplementedException();
            }
        }
    }
}
