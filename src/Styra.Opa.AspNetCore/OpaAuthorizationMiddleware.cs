using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
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
    private readonly RequestDelegate _next;
    private readonly ILogger<OpaAuthorizationMiddleware> _logger;

    public OpaAuthorizationMiddleware(
        RequestDelegate next,
        ILogger<OpaAuthorizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    // HttpContext context, IOpaAuthorizationSerivce opaAuthzService)
    {
        // 1 - if the request is not authenticated, nothing to do
        if (context.User.Identity == null || !context.User.Identity.IsAuthenticated)
        {
            await _next(context);
            return;
        }

        var cancellationToken = context.RequestAborted;

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
}
