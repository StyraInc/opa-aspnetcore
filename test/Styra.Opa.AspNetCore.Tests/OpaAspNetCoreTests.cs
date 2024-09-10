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
    private readonly TestServer _server;
    private HttpClient _client;

    public OpaAspNetCoreTests(OPAContainerFixture opaFixture, EOPAContainerFixture eopaFixture)
    {
        _containerOpa = opaFixture.GetContainer();
        _containerEopa = eopaFixture.GetContainer();

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

        // Create the TestServer
        _server = new TestServer(builder);
        _client = _server.CreateClient();
        //_client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
    }

    private OpaApiClient GetOpaApiClient()
    {
        // Construct the request URI by specifying the scheme, hostname, assigned random host port, and the endpoint "uuid".
        var requestUri = new UriBuilder(Uri.UriSchemeHttp, _containerOpa.Hostname, _containerOpa.GetMappedPublicPort(8181)).Uri;

        // Send an HTTP GET request to the specified URI and retrieve the response as a string.
        return new OpaApiClient(serverIndex: 0, serverUrl: requestUri.ToString());
    }

    private OpaApiClient GetEOpaApiClient()
    {
        // Construct the request URI by specifying the scheme, hostname, assigned random host port, and the endpoint "uuid".
        var requestUri = new UriBuilder(Uri.UriSchemeHttp, _containerEopa.Hostname, _containerEopa.GetMappedPublicPort(8181)).Uri;

        // Send an HTTP GET request to the specified URI and retrieve the response as a string.
        return new OpaApiClient(serverIndex: 0, serverUrl: requestUri.ToString());
    }

    [Fact]
    public async Task OpenApiClientRBACTestcontainersTest()
    {
        var client = GetOpaApiClient();

        // Exercise the low-level OPA C# SDK.
        var req = new ExecutePolicyWithInputRequest()
        {
            Path = "policy/decision_always_true",
            RequestBody = new ExecutePolicyWithInputRequestBody()
            {
                Input = Input.CreateMapOfAny(
                        new Dictionary<string, object>() {
                    { "identity", "secret" },
                }),
            },
        };

        var res = await client.ExecutePolicyWithInputAsync(req);
        var resultMap = res.SuccessfulPolicyResponse?.Result?.MapOfAny;

        // Ensure we got back the expected fields from the eval.
        Assert.Equal(true, resultMap?.GetValueOrDefault("decision", false));
    }

    [Fact]
    public async Task MiddlewareTest_ReturnsNotFoundForRequest()
    {
        // using var host = await new WebHostBuilder()
        //     .ConfigureWebHost(webBuilder =>
        //     {
        //         webBuilder
        //             .UseTestServer()
        //             .ConfigureServices(services =>
        //             {
        //                 services.AddMyServices();
        //             })
        //             .Configure(app =>
        //             {
        //                 app.UseMiddleware<OpaAuthorizationMiddleware>();
        //             });
        //     })
        //     .StartAsync();

        // var response = await host.GetTestClient().GetAsync("/");
        var response = await _client.GetAsync("/hello");
        Assert.False(response.IsSuccessStatusCode);
        Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
        // var responseBody = await response.Content.ReadAsStringAsync();
        // Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task MiddlewareTest_AuthenticatedTest()
    {
        // using var host = await new WebHostBuilder()
        //     .ConfigureWebHost(webBuilder =>
        //     {
        //         webBuilder
        //             .UseTestServer()
        //             .ConfigureServices(services =>
        //             {
        //                 services.AddMyServices();
        //             })
        //             .Configure(app =>
        //             {
        //                 app.UseMiddleware<OpaAuthorizationMiddleware>();
        //             });
        //     })
        //     .StartAsync();

        // var response = await host.GetTestClient().GetAsync("/");
        Console.WriteLine("Value before {0}", _client.DefaultRequestHeaders.Authorization);
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test", "test");
        Console.WriteLine("Value after {0}", _client.DefaultRequestHeaders.Authorization);
        var response = await _client.GetAsync("/hello");
        Assert.True(response.IsSuccessStatusCode);
        var responseBody = await response.Content.ReadAsStringAsync();
        Assert.Equal("Hello Tests", responseBody);

        // Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }
}
