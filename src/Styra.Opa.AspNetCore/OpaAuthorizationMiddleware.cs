using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Styra.Opa.AspNetCore;

/// <summary>
///  This interface can be used to expose additional information to the OPA
///  policy via the context field. Data returned by GetContextData() is placed
///  in input.context.data. The returned object must be JSON serializeable.
/// </summary>
interface IContextDataProvider
{
    object GetContextData();
}

/// <summary>
///  This helper class allows creating a ContextDataProvider which always returns
///  the same constant value. This is useful for tests, and also for situations
///  where the extra data to inject does not change during runtime
/// </summary>
public class ConstantContextDataProvider : IContextDataProvider
{
    private object data;

    public ConstantContextDataProvider(object newData)
    {
        data = newData;
    }

    public object GetContextData()
    {
        return data;
    }
}

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

    //private ContextDataProvider ctxProvider; // TODO
    private OpaClient _opa;

    // Fields needed for the middleware-specific functionality.
    private readonly RequestDelegate _next;
    private readonly ILogger<OpaAuthorizationMiddleware> _logger;

    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        _logger.LogInformation("OpaAuthorizationMiddleware initialized.");
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
        _logger.LogInformation("OpaAuthorizationMiddleware initialized.");
        _opa = opa;
        reasonKey = "en";
    }

    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger,
        OpaClient opa,
        string opaPath)
    {
        _next = next;
        _logger = logger;
        _logger.LogInformation("OpaAuthorizationMiddleware initialized.");
        _opa = opa;
        _opaPath = opaPath;
        reasonKey = "en";
    }

    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger,
        string opaPath)
    {
        _next = next;
        _logger = logger;
        _logger.LogInformation("OpaAuthorizationMiddleware initialized.");
        _opa = defaultOPAClient();
        _opaPath = opaPath;
        reasonKey = "en";
    }

    // TODO: Add the ContextDataProvider combinations.
    // TODO: Add serviceprovider variants, to allow for app-wide DI to work.

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

    private Dictionary<string, object> makeRequestInput(HttpContext context)
    {
        var subjectId = context.User.Identity?.Name ?? "";
        //var subjectDetails = context.User ?? "";
        var subjectClaims = JsonConvert.DeserializeObject(JsonConvert.SerializeObject(context.User.Claims, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));

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

        // TODO: Add RequestContextProvider insert logic here.
        // if (this.ctxProvider != null) {
        //     Object contextData = this.ctxProvider.getContextData(authentication, object);
        //     ctx.put("data", contextData);
        // }

        Dictionary<string, object> outMap = new Dictionary<string, object>() {
            { "subject", new Dictionary<string, object>() {
                { "type", SubjectType },
                { "id", subjectId },
                //{ "details", subjectDetails },
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
        Dictionary<string, object> inputMap = makeRequestInput(context);
        _logger.LogTrace("OPA input for request: {}", inputMap);
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
            _logger.LogTrace("OPA response is: {}", resp);
        }
        catch (OpaException e)
        {
            _logger.LogError("caught exception from OPA client: {}", e);
            return null;
        }
        return resp;
    }
}
