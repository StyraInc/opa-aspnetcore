using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Styra.Opa.OpenApi;
using Styra.Opa.OpenApi.Models.Components;
using Styra.Opa.OpenApi.Models.Requests;
using System.Net;

namespace Styra.Opa.AspNetCore.Tests;

public class OpaAspNetCoreTests : IClassFixture<OPAContainerFixture>, IClassFixture<EOPAContainerFixture>
{
    public IContainer _containerOpa;
    public IContainer _containerEopa;
    private readonly TestServer _server;
    private readonly HttpClient _client;

    public OpaAspNetCoreTests(OPAContainerFixture opaFixture, EOPAContainerFixture eopaFixture)
    {
        _containerOpa = opaFixture.GetContainer();
        _containerEopa = eopaFixture.GetContainer();

        var builder = new WebHostBuilder()
           .ConfigureServices(services =>
           {
               // Add any required services
               //services.AddMyServices();
           })
           .Configure(app =>
           {
               // Configure the middleware pipeline
               app.UseMiddleware<Styra.Opa.AspNetCore.OpaAuthorizationMiddleware>();
               // Add other middleware as needed
           });

        // Create the TestServer
        _server = new TestServer(builder);
        _client = _server.CreateClient();
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
        var response = await _client.GetAsync("/");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        // Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }
}
