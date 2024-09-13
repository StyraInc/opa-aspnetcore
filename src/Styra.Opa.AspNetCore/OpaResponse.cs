
using Newtonsoft.Json;

namespace Styra.Opa.AspNetCore;

public class OpaResponse
{

    [JsonProperty("decision")]
    public bool Decision { get; set; }

    [JsonProperty("context")]
    public OpaResponseContext? Context { get; set; }

    /// <summary>
    ///  Wraps OPAResponseContext.GetReasonForDecision(). If the context is
    ///  omitted (which the spec permits), then it returns null.
    /// </summary>
    public string? GetReasonForDecision(string searchKey)
    {
        return Context?.GetReasonForDecision(searchKey);
    }

}