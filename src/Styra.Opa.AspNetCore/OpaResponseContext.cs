using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Styra.Opa.AspNetCore;
public class OpaResponseContext
{

    [JsonProperty("id")]
    private string? ID { get; set; }

    [JsonProperty("reason_admin")]
    private Dictionary<string, string>? ReasonAdmin { get; set; }

    [JsonProperty("reason_user")]
    private Dictionary<string, string>? ReasonUser { get; set; }

    [JsonProperty("data")]
    private Dictionary<string, object>? Data { get; set; }

    /// <summary>
    ///  This method selects an appropriate reason to use for creating ASP.NET Core
    ///  authorization decisions. Currently, it will select the search key if it
    ///  is present in the reason_user object, and if not it will select the key
    ///  which sorts first from reason_user. It will not consider data in
    ///  reason_admin.
    /// </summary>
    public string? GetReasonForDecision(string searchKey)
    {
        if (ReasonUser is null)
        {
            return null;
        }

        if (ReasonUser.TryGetValue(searchKey, out string? reason))
        {
            return reason;
        }

        return ReasonUser?.Keys.OrderBy(k => k).FirstOrDefault();
    }
}