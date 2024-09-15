using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Styra.Opa.AspNetCore;

public static class HttpContextExtensions
{
    public static async ValueTask WriteAccessDeniedResponse(
        this HttpContext context,
        string? title = null,
        string? reason = null,
        int? statusCode = null,
        CancellationToken cancellationToken = default)
    {
        var problem = new
        {
            Instance = context.Request.Path,
            Title = title ?? "Access denied",
            Status = statusCode ?? 403,
            Reason = reason,
        };

        context.Response.StatusCode = problem.Status;
        await context.Response.WriteAsync(
            JsonConvert.SerializeObject(problem, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore }),
            cancellationToken);
    }
}

/// <summary>
/// We do not subclass from Microsoft's AuthorizationMiddleware because we
/// are intentionally operating outside of the policy-based authorization
/// system they provide.
/// </summary>
public class OpaAuthorizationMiddleware
{
    // Fields useful for the I/O schema.
    private string SubjectType = "aspnetcore_authentication";
    private string RequestResourceType = "endpoint";
    private string RequestContextType = "http";

    // If opaPath is null, then we assume the user wants to use the default path.
    private string? _opaPath;

    /// <summary>
    /// The "preferred" key where the access decision reason should be
    /// searched for in the OpaResponse object. A default value of 'en' is used.
    /// If the selected key is not present in the response, the lexicographically
    /// first key is used instead from the sorted key list.
    /// </summary>
    private string reasonKey { get; set; }

    private OpaClient _opa;

    private IContextDataProvider? _contextProvider;

    // Fields needed for the middleware-specific functionality.
    private readonly RequestDelegate _next;
    private readonly ILogger<OpaAuthorizationMiddleware> _logger;

    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        _logger.LogInformation("AAA OpaAuthorizationMiddleware initialized.");
        _opa = defaultOPAClient();
        reasonKey = "en";
    }

    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger,
        OpaClient opa)
    {
        _next = next;
        _logger = logger;
        _opa = opa;
        reasonKey = "en";
        _logger.LogInformation("OpaAuthorizationMiddleware initialized.");
    }

    // Named optional parameters allow the user to be selective at object creation time.
    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger,
        OpaClient? opa = null,
        string? opaPath = null,
        IContextDataProvider? dataProvider = null)
    {
        _next = next;
        _logger = logger;
        _opa = opa ?? defaultOPAClient();
        _opaPath = opaPath;
        _contextProvider = dataProvider;
        reasonKey = "en";
        _logger.LogInformation("OpaAuthorizationMiddleware initialized.");
    }

    // TODO: Add ServiceProvider variants, to allow for app-wide DI to work.

    /// <summary>
    /// InvokeAsync hooks into the middleware pipeline for a request, and
    /// either rejects the request with an Access Denied response, or
    /// allows it through to other middleware or the main application to
    /// process further.
    /// </summary>
    /// <param name="context">HttpContext for the incoming request.</param>
    /// <returns></returns>
    public async Task InvokeAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;

        // If the request is not authenticated, default deny.
        if (context.User.Identity == null || !context.User.Identity.IsAuthenticated)
        {
            _logger.LogTrace("unauthenticated request, default-denying access");
            await context.WriteAccessDeniedResponse(
                "Access denied",
                "access denied by policy",
                null,
                cancellationToken);
            return;
        }

        // Launch OPA request, default-deny if null response.
        OpaResponse? resp = await opaRequest(context);
        if (resp is null)
        {
            _logger.LogTrace("OPA provided a null response, default-denying access");
            await context.WriteAccessDeniedResponse(
                "Access denied",
                "access denied by policy",
                null,
                cancellationToken);
            return;
        }

        // Allow/Deny based on the decision.
        bool allow = resp.Decision;
        string reason = resp.GetReasonForDecision(reasonKey) ?? "access denied by policy";
        if (!allow)
        {
            await context.WriteAccessDeniedResponse(
                "Access denied",
                reason,
                null,
                cancellationToken);
            return;
        }

        _logger.LogTrace("access verified successfully");
        await _next(context);
    }

    private Dictionary<string, object> MakeRequestInput(HttpContext context)
    {
        var subjectId = context.User.Identity?.Name ?? "";
        //var subjectDetails = principal ?? "";
        var subjectClaims = JsonConvert.DeserializeObject(JsonConvert.SerializeObject(context.User.Claims, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore })) ?? new { };

        string resourceId = context.Request.Path;
        string actionName = context.Request.Method;
        string actionProtocol = context.Request.Protocol;
        Dictionary<string, string> headers = context.Request.Headers.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToString());

        string contextRemoteAddr = context.Connection.RemoteIpAddress?.ToString() ?? "";
        string contextRemoteHost = context.Request.Host.ToString();
        int contextRemotePort = context.Connection.RemotePort;

        Dictionary<string, object> ctx = new Dictionary<string, object>() {
            { "type", RequestContextType },
            { "host", contextRemoteHost },
            { "ip", contextRemoteAddr },
            { "port", contextRemotePort },
        };

        if (_contextProvider is not null)
        {
            object contextData = _contextProvider.GetContextData(context);
            ctx.Add("data", contextData);
        }

        Dictionary<string, object> outMap = new Dictionary<string, object>() {
            { "subject", new Dictionary<string, object>() {
                { "type", SubjectType },
                { "id", subjectId },
                { "claims", subjectClaims },
            }},
            { "resource", new Dictionary<string, object>() {
                { "type", RequestResourceType },
                { "id", resourceId },
            }},
            { "action", new Dictionary<string, object>() {
                { "name", actionName },
                { "protocol", actionProtocol },
                { "headers", headers },
            }},
            { "context", ctx },
        };

        return outMap;
    }

    private static OpaClient defaultOPAClient()
    {
        string opaURL = System.Environment.GetEnvironmentVariable("OPA_URL") ?? "http://localhost:8181";
        return new OpaClient(opaURL);
    }

    /// <summary>
    /// This method abstracts over the OPA evaluation, and automatically
    /// selects the default rule, or a rule based on the provided path.
    /// </summary>
    private async Task<OpaResponse?> opaRequest(HttpContext context)
    {
        Dictionary<string, object> inputMap = MakeRequestInput(context);
        _logger.LogTrace("OPA input for request: {}", JsonConvert.SerializeObject(inputMap));
        OpaResponse? resp = null;
        try
        {
            if (_opaPath is not null)
            {
                _logger.LogTrace("OPA path is {}", _opaPath);
                resp = await _opa.evaluate<OpaResponse>(_opaPath, inputMap);
            }
            else
            {
                _logger.LogTrace("Using default OPA path");
                resp = await _opa.evaluateDefault<OpaResponse>(inputMap);
            }
            _logger.LogTrace("OPA response is: {}", JsonConvert.SerializeObject(resp));
        }
        catch (OpaException e)
        {
            _logger.LogError("caught exception from OPA client: {}", e);
            return null;
        }
        return resp;
    }
}
