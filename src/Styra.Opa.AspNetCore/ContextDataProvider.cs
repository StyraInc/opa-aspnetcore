using Microsoft.AspNetCore.Http;

namespace Styra.Opa.AspNetCore;

/// <summary>
/// This interface can be used to expose additional information to the OPA
/// policy via the context field. Data returned by GetContextData() is placed
/// in input.context.data. The returned object must be JSON serializeable.
/// </summary>
public interface IContextDataProvider
{
    object GetContextData(HttpContext context);
}

/// <summary>
/// This helper class allows creating a ContextDataProvider which always returns
/// the same constant value. This is useful for tests, and also for situations
/// where the extra data to inject does not change during runtime.
/// </summary>
public class ConstantContextDataProvider : IContextDataProvider
{
    private object data;

    public ConstantContextDataProvider(object newData)
    {
        data = newData;
    }

    public object GetContextData(HttpContext context)
    {
        return data;
    }
}