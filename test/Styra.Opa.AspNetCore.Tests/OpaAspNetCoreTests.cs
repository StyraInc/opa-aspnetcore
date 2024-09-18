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
using Newtonsoft.Json.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Styra.Opa.AspNetCore.Tests;

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
                { "host", "" },
                // { "host", "example.com" }, // Note(philip): This isn't avaailable in the IHttpRequestFeature mock.
                { "ip", "192.0.2.123" },
                { "port", 0 },
                { "type", "http" },
                { "data", new Dictionary<string, object>() {
                    { "hello", "world" },
                }}
            }},
            { "resource", new Dictionary<string, object>() {
                { "id", "/unit/test" },
                { "type", "endpoint" },
            }},
            { "subject", new Dictionary<string, object>() {
                { "claims", new List<object>() {
                    new Dictionary<string, object>() {
                        { "Issuer", "LOCAL AUTHORITY" },
                        { "OriginalIssuer", "LOCAL AUTHORITY" },
                        { "Properties", new Dictionary<string, object>() },
                        { "Type", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" },
                        { "Subject", new Dictionary<string, object> () {
                            { "Actor", null! },
                            { "AuthenticationType", "TestAuthType" },
                            { "BootstrapContext", null! },
                            { "Claims", new List<object>() },
                            { "IsAuthenticated", true },
                            { "Label", null! },
                            { "Name", "testuser" },
                            { "NameClaimType", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" },
                            { "RoleClaimType", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" },
                        }},
                        { "Value", "testuser" },
                        { "ValueType", "http://www.w3.org/2001/XMLSchema#string" },
                    },
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
        string expectedJson = JsonConvert.SerializeObject(expect, Formatting.Indented);

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
            Protocol = "HTTP/1.1",
            Method = "GET",
            Path = "/unit/test",
            Headers = new HeaderDictionary() { { "UnitTestHeader", "123abc" }, }
        });
        // Mock the ClaimsPrincipal.
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, "testuser"),
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

        string actualJson = JsonConvert.SerializeObject(actual, Formatting.Indented);
        string diff = JsonDiffer.Diff(JObject.Parse(expectedJson), JObject.Parse(actualJson));
        if (diff.Length > 0)
        {
            Assert.Fail(string.Format("Unexpected difference between expected and actual Json (+want/-got):\n{0}", diff));
        }

        Assert.Equal(expect.Decision, actual.Decision);
        Assert.Equal(expect.Context.ID, actual.Context?.ID);
        Assert.Equal(expect.Context.ReasonUser, actual.Context?.ReasonUser);

        Assert.Equal("echo rule always allows", actual.GetReasonForDecision("en"));
        Assert.Equal("other reason key", actual.GetReasonForDecision("other"));
        Assert.Equal("echo rule always allows", actual.GetReasonForDecision("nonexistant"));
    }
}

// Thanks to perplexity.ai for this class definition.
public class JsonDiffer
{
    public static string Diff(JToken left, JToken right, string path = "")
    {
        var sb = new StringBuilder();

        if (JToken.DeepEquals(left, right))
        {
            return sb.ToString();
        }

        if (left.Type != right.Type)
        {
            sb.AppendLine($"- {path}: {left}");
            sb.AppendLine($"+ {path}: {right}");
            return sb.ToString();
        }

        switch (left.Type)
        {
            case JTokenType.Object:
                DiffObjects((left as JObject)!, (right as JObject)!, path, sb);
                break;
            case JTokenType.Array:
                DiffArrays((left as JArray)!, (right as JArray)!, path, sb);
                break;
            default:
                if (!JToken.DeepEquals(left, right))
                {
                    sb.AppendLine($"- {path}: {left}");
                    sb.AppendLine($"+ {path}: {right}");
                }
                break;
        }

        return sb.ToString();
    }

    private static void DiffObjects(JObject left, JObject right, string path, StringBuilder sb)
    {
        var addedKeys = right.Properties().Select(p => p.Name).Except(left.Properties().Select(p => p.Name));
        var removedKeys = left.Properties().Select(p => p.Name).Except(right.Properties().Select(p => p.Name));
        var commonKeys = left.Properties().Select(p => p.Name).Intersect(right.Properties().Select(p => p.Name));

        foreach (var key in addedKeys)
        {
            sb.AppendLine($"+ {CombinePath(path, key)}: {right[key]}");
        }

        foreach (var key in removedKeys)
        {
            sb.AppendLine($"- {CombinePath(path, key)}: {left[key]}");
        }

        foreach (var key in commonKeys)
        {
            sb.Append(Diff(left[key]!, right[key]!, CombinePath(path, key)));
        }
    }

    private static void DiffArrays(JArray left, JArray right, string path, StringBuilder sb)
    {
        var minLength = Math.Min(left.Count, right.Count);

        for (int i = 0; i < minLength; i++)
        {
            sb.Append(Diff(left[i], right[i], $"{path}[{i}]"));
        }

        if (left.Count < right.Count)
        {
            for (int i = left.Count; i < right.Count; i++)
            {
                sb.AppendLine($"+ {path}[{i}]: {right[i]}");
            }
        }
        else if (left.Count > right.Count)
        {
            for (int i = right.Count; i < left.Count; i++)
            {
                sb.AppendLine($"- {path}[{i}]: {left[i]}");
            }
        }
    }

    private static string CombinePath(string basePath, string key)
    {
        return string.IsNullOrEmpty(basePath) ? key : $"{basePath}.{key}";
    }
}