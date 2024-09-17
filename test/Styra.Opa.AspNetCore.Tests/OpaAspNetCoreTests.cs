using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Styra.Opa.AspNetCore.Tests;

// 
// Source: https://learn.microsoft.com/en-us/aspnet/core/test/integration-tests?view=aspnetcore-3.1#mock-authentication
public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    [Obsolete]
    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
#pragma warning disable CS0618 // Type or member is obsolete
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
#pragma warning restore CS0618 // Type or member is obsolete
        : base(options, logger, encoder, clock)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[] { new Claim(ClaimTypes.Name, "Test user") };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, "Test");

        var result = AuthenticateResult.Success(ticket);
        this.Logger.LogTrace("Using TestAuthHandler authentication.");

        return Task.FromResult(result);
    }
}

public class OpaAspNetCoreTests : IClassFixture<OPAContainerFixture>, IClassFixture<EOPAContainerFixture>
{
    public IContainer _containerOpa;
    public IContainer _containerEopa;

    public IWebHostBuilder GetWebHostBuilder()
    {
        var builder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                // Add any required services
                services.AddAuthentication(opts => { opts.DefaultScheme = "DynamicAuthenticationScheme"; })
                     .AddCookie() // Not used, except for unauth tests.
                     .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                         "Test", options => { })
                     .AddPolicyScheme(
                         "DynamicAuthenticationScheme",
                         "Default system policy",
                         cfgOpts => cfgOpts.ForwardDefaultSelector = ctx =>
                             ctx.Request.Headers.ContainsKey("Authorization")
                                 ? "Test"
                                 : Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
                services.AddRouting();
                services.AddLogging(builder => builder.SetMinimumLevel(LogLevel.Trace).AddConsole());
            });
        return builder;
    }

    public OpaAspNetCoreTests(OPAContainerFixture opaFixture, EOPAContainerFixture eopaFixture)
    {
        _containerOpa = opaFixture.GetContainer();
        _containerEopa = eopaFixture.GetContainer();
        //_client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
    }

    private OpaClient GetOpaClient()
    {
        // Construct the request URI by specifying the scheme, hostname, assigned random host port, and the endpoint "uuid".
        var requestUri = new UriBuilder(Uri.UriSchemeHttp, _containerOpa.Hostname, _containerOpa.GetMappedPublicPort(8181)).Uri;
        return new OpaClient(serverUrl: requestUri.ToString());
    }

    private OpaClient GetEOpaClient()
    {
        var requestUri = new UriBuilder(Uri.UriSchemeHttp, _containerEopa.Hostname, _containerEopa.GetMappedPublicPort(8181)).Uri;
        return new OpaClient(serverUrl: requestUri.ToString());
    }

    [Fact]
    public async Task TestE2EOpaAuthorizationMiddlewareSimpleAllow()
    {
        var opac = GetOpaClient();
        // Create the TestServer + Client
        var builder = GetWebHostBuilder().Configure(app =>
            {
                // Configure the middleware pipeline
                app.UseRouting();
                app.UseAuthentication();
                app.UseMiddleware<OpaAuthorizationMiddleware>(opac, "policy/decision_always_true");
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/hello", async (context) => await context.Response.WriteAsync("Hello Tests"));
                });
            });

        var server = new TestServer(builder);
        var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test", "test");

        var response = await client.GetAsync("/hello");
        Assert.True(response.IsSuccessStatusCode);
        var responseBody = await response.Content.ReadAsStringAsync();
        Assert.Equal("Hello Tests", responseBody);
    }

    [Fact]
    public async Task TestE2EOpaAuthorizationMiddlewareSimpleDeny()
    {
        var opac = GetOpaClient();
        // Create the TestServer + Client
        var builder = GetWebHostBuilder().Configure(app =>
            {
                // Configure the middleware pipeline
                app.UseRouting();
                app.UseAuthentication();
                app.UseMiddleware<OpaAuthorizationMiddleware>(opac, "policy/decision_always_false");
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/hello", async (context) => await context.Response.WriteAsync("Hello Tests"));
                });
            });

        var server = new TestServer(builder);
        var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test", "test");

        var response = await client.GetAsync("/hello");
        Assert.False(response.IsSuccessStatusCode);
        var responseBody = await response.Content.ReadAsStringAsync();
        Assert.Contains("Access denied", responseBody);
    }

    [Fact]
    public async Task TestMiddlewareJSONFormatEcho()
    {
        // By reading back the input, we can make sure the OPA input has the
        // right structure and content.
        Dictionary<string, object> expectData = new Dictionary<string, object>() {
            { "action", new Dictionary<string, object>() {
                { "headers", new Dictionary<string, object>() {
                    { "UnitTestHeader", "123abc" },
                }},
                { "name", "GET" },
                { "protocol", "HTTP/1.1" }
            }},
            { "context", new Dictionary<string, object>() {
                { "host", "example.com" },
                { "ip", "192.0.2.123" },
                { "port", 0 },
                { "type", "http" },
                { "data", new Dictionary<string, object>() {
                    { "hello", "world" },
                }}
            }},
            { "resource", new Dictionary<string, object>() {
                { "id", "unit/test" },
                { "type", "endpoint" },
            }},
            { "subject", new Dictionary<string, object>() {
                { "claims", new List<object>() {
                    new Dictionary<string, object>() {{ "authority", "ROLE_USER" }},
                    new Dictionary<string, object>() {{ "authority", "ROLE_ADMIN" }}
                }},
                { "details", new Dictionary<string, object>() {
                    { "remoteAddress", "192.0.2.123" },
                    { "sessionId", "null" }
                }},
                { "id", "testuser" },
                { "type", "aspnetcore_authentication" }
            }}
        };

        OpaResponseContext expectCtx = new OpaResponseContext();
        expectCtx.ReasonUser = new Dictionary<string, string>() {
            { "en", "echo rule always allows" },
            { "other", "other reason key" },
        };
        expectCtx.ID = "0";
        expectCtx.Data = expectData;

        OpaResponse expect = new OpaResponse();
        expect.Decision = true;
        expect.Context = expectCtx;

        IContextDataProvider prov = new ConstantContextDataProvider(new Dictionary<string, string>() {
            { "hello", "world" }
        });


        var opac = GetOpaClient();
        var middleware = new OpaAuthorizationMiddleware(new RequestDelegate((HttpContext hc) => { return Task.CompletedTask; }), null, opac, "policy/echo", prov);

        // Generate the extensive mocking required for the request to be processed correctly.
        var features = new FeatureCollection();
        // Mock the HttpConnection.
        features.Set<IHttpConnectionFeature>(new HttpConnectionFeature
        {
            RemoteIpAddress = IPAddress.Parse("192.0.2.123"),
            RemotePort = 0,
        });
        // Mock the HttpRequest.
        features.Set<IHttpRequestFeature>(new HttpRequestFeature
        {
            Method = "GET",
            Path = "/unit/test",
        });
        // Mock the ClaimsPrincipal.
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim(ClaimTypes.Role, "User"),
        };
        var identity = new ClaimsIdentity(claims, "TestAuthType");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        features.Set<IHttpAuthenticationFeature>(new HttpAuthenticationFeature
        {
            User = claimsPrincipal
        });
        // Pull it all together into the mocked HttpContext.
        var httpContext = new DefaultHttpContext(features);

        var actual = await middleware.OpaRequest(httpContext);
        if (actual is null)
        {
            Assert.Fail("Test received a null OpaResponse");
        }

        // TODO: Add JSON diffing, as in the OPA Spring Boot SDK.

        Assert.Equal(expect.Decision, actual.Decision);
        Assert.Equal(expect.Context.ID, actual.Context?.ID);
        Assert.Equal(expect.Context.ReasonUser, actual.Context?.ReasonUser);

        Assert.Equal("echo rule always allows", actual.GetReasonForDecision("en"));
        Assert.Equal("other reason key", actual.GetReasonForDecision("other"));
        Assert.Equal("echo rule always allows", actual.GetReasonForDecision("nonexistant"));
    }
}
