using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Styra.Opa.OpenApi;
using Styra.Opa.OpenApi.Models.Components;
using Styra.Opa.OpenApi.Models.Requests;
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
        this.Logger.LogWarning("RUNNING!");

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
            })
            .Configure(app =>
            {
                // Configure the middleware pipeline
                app.UseRouting();
                app.UseAuthentication();
                app.UseMiddleware<OpaAuthorizationMiddleware>();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/hello", async (context) =>
                    {
                        foreach (var header in context.Request.GetTypedHeaders().Headers)
                        {
                            Console.WriteLine(header);
                        }

                        await context.Response.WriteAsync("Hello Tests");
                    });
                });
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
    public async Task MiddlewareTest_ReturnsNotFoundForRequest()
    {
        // Create the TestServer + Client
        var server = new TestServer(GetWebHostBuilder());
        var client = server.CreateClient();

        // var response = await host.GetTestClient().GetAsync("/");
        var response = await client.GetAsync("/hello");
        Assert.False(response.IsSuccessStatusCode);
        Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
        // var responseBody = await response.Content.ReadAsStringAsync();
        // Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task MiddlewareTest_AuthenticatedTest()
    {
        var opac = GetOpaClient();
        // Create the TestServer + Client
        var builder = GetWebHostBuilder().Configure(app =>
            {
                app.UseAuthentication();
                app.UseMiddleware<OpaAuthorizationMiddleware>(opac);
            });
        var server = new TestServer(builder);
        var client = server.CreateClient();

        Console.WriteLine("Value before {0}", client.DefaultRequestHeaders.Authorization);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test", "test");
        Console.WriteLine("Value after {0}", client.DefaultRequestHeaders.Authorization);
        var response = await client.GetAsync("/hello");
        //Assert.True(response.IsSuccessStatusCode);
        var responseBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine(responseBody);
        Assert.Equal("Hello Tests", responseBody);

        // Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task TestOpaHealth()
    {
        // Create the TestServer + Client
        var server = new TestServer(GetWebHostBuilder());
        var client = server.CreateClient();
    }

    [Fact]
    public async Task TestOpaHealthAlternate()
    {

    }

    [Fact]
    public async Task TestOpaAuthorizationMiddlewareSimpleAllow()
    {

    }

    [Fact]
    public async Task TestOpaAuthorizationMiddlewareSimpleDeny()
    {

    }

    [Fact]
    public async Task TestOpaAuthorizationMiddlewareSimpleAllowVerify()
    {

    }

    [Fact]
    public async Task TestOpaAuthorizationMiddlewareSimpleDenyVerify()
    {

    }

    [Fact]
    public async Task TestOpaAuthorizationMiddlewareEcho()
    {

    }
}
