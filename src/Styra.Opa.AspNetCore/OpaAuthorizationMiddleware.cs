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
        int? statusCode = null,
        CancellationToken cancellationToken = default)
    {
        // var problem = new ProblemDetails
        // {
        //     Instance = context.Request.Path,
        //     Title = title ?? "Access denied",
        //     Status = statusCode ?? Status403Forbidden
        // };
        // context.Response.StatusCode = problem.Status.Value;

        // await context.Response.WriteAsync(JsonSerializer.Serialize(problem, JsonSerializerOptions),
        //     cancellationToken);
    }
}
public class OpaAuthorizationMiddleware
{
    // Fields useful for the I/O schema.
    private string SubjectType = "aspnetcore_authentication";
    private string RequestResourceType = "endpoint";
    private string RequestContextType = "http";

    // If opaPath is null, then we assume the user wants to use the default path.
    private string opaPath;
    private string reasonKey;
    //private ContextDataProvider ctxProvider; // TODO
    private OpaClient opa;

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
    }

    public async Task InvokeAsync(HttpContext context)
    // HttpContext context, IOpaAuthorizationSerivce opaAuthzService)
    {
        _logger.LogWarning("user identity: {ident}, is auth?: {authd}", context.User.Identity.Name, context.User.Identity.IsAuthenticated);
        // 1 - if the request is not authenticated, nothing to do
        if (context.User.Identity == null || !context.User.Identity.IsAuthenticated)
        {

            _logger.LogWarning("unauth context is: {context}", context);
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync(JsonConvert.SerializeObject(new { status = "Not Authorized" }), context.RequestAborted);

            // await context.Response.WriteAsync(JsonSerializer.Serialize(problem, JsonSerializerOptions),
            //     cancellationToken);
            //await _next(context);
            return;
        }

        var cancellationToken = context.RequestAborted;
        _logger.LogWarning("authn'd context is: {context}, user: {user}", context, context.User.Identity);

        // 2. The 'sub' claim is how we find the user in our system
        // var userSub = context.User.FindFirst(StandardJwtClaimTypes.Subject)?.Value;
        // if (string.IsNullOrEmpty(userSub))
        // {
        //     await context.WriteAccessDeniedResponse(
        //       "User 'sub' claim is required",
        //       cancellationToken: cancellationToken);
        //     return;
        // }

        // // 3 - Now we try to get the user permissions (as ClaimsIdentity)
        // var allowed = await opaAuthzService.evaluate<bool>(userSub, cancellationToken);
        // if (permissionsIdentity == null)
        // {
        //     _logger.LogWarning("User {sub} does not have permissions", userSub);

        //     await context.WriteAccessDeniedResponse(cancellationToken: cancellationToken);
        //     return;
        // }

        // // 4 - User has permissions
        // // so we add the extra identity to the ClaimsPrincipal
        // context.User.AddIdentity(permissionsIdentity);
        await _next(context);
    }

    private Dictionary<string, object> makeRequestInput(HttpContext context)
    {
        var subjectId = context.User.Identity?.Name ?? "";
        //var subjectDetails = context.User ?? "";
        var subjectClaims = context.User.Claims;

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
}
