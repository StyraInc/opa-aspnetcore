# OPA ASP.NET Core SDK

> [!IMPORTANT]
> The documentation for this SDK lives at [https://docs.styra.com/sdk](https://docs.styra.com/sdk), with reference documentation available at [https://styrainc.github.io/opa-aspnetcore/docs](https://styrainc.github.io/opa-aspnetcore/docs)

You can use the Styra OPA ASP.NET Core SDK to connect [Open Policy Agent](https://www.openpolicyagent.org/) and [Enterprise OPA](https://www.styra.com/enterprise-opa/) deployments to your [ASP.NET Core](https://spring.io/projects/spring-boot) applications using the included [Middleware](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-8.0) implementation.

> [!IMPORTANT]
> Would you prefer a plain C# API instead of ASP.NET Core? Check out the [OPA C# SDK](https://github.com/StyraInc/opa-csharp).

<!--## SDK Installation

This package is published on NuGet as [`Styra.Opa.AspNetCore`](https://www.nuget.org/packages/Styra.Opa.AspNetCore). The NuGet page includes up-to-date instructions on how to add it as a dependency to your C# project.

-->

## SDK Example Usage (high-level)

```csharp
using Styra.Opa.AspNetCore;

// ...

string opaURL = System.Environment.GetEnvironmentVariable("OPA_URL") ?? "http://localhost:8181";
OPAClient opa = new OPAClient(opaURL);

var builder = new WebHostBuilder()
    .ConfigureServices(services =>
    {
        services.AddAuthentication( /* ... your authentication setup here ... */ );
        services.AddRouting();
        // ...
    }).Configure(app =>
    {
        app.UseRouting();
        app.UseAuthentication();
        app.UseMiddleware<OpaAuthorizationMiddleware>(opa, "authz/exampleapp/routes/allow");
        // ...
        // Your controller/routes added here.
    });

var app = builder.Build();
app.Run();
```

## Policy Input/Output Schema

Documentation for the required input and output schema of policies used by the OPA ASP.NET Core SDK can be found [here](https://docs.styra.com/sdk/aspnetcore/reference/input-output-schema)

## Build Instructions

**To build the SDK**, use `dotnet build`, the resulting JAR will be placed in `./build/libs/api.jar`.

**To build the documentation** site, run `docfx docs/docfx.json -o OUTPUT_DIR`. You should replace `OUTPUT_DIR` with a directory on your local system where you would like the generated docs to be placed (the default behavior without `-o` will place the generated HTML docs site under the `docs/_site` folder in this repo). You can also preview the documentation site using `docfx docs/docfx.json --serve`, which will serve the docs on `http://localhost:8080` until you use Ctrl+C to exit.

**To run the unit tests**, you can use `dotnet test`.

## Community

For questions, discussions and announcements related to Styra products, services and open source projects, please join
the Styra community on [Slack](https://communityinviter.com/apps/styracommunity/signup)!

## Development

For development docs, see [DEVELOPMENT.md](./DEVELOPMENT.md).
