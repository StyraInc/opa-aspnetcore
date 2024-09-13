using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Styra.Opa.AspNetCore;
public class OpaResponseContext
{

    [JsonProperty("id")]
    private string? id { get; set; }

    [JsonProperty("reason_admin")]
    private Dictionary<string, string>? reasonAdmin { get; set; }

    [JsonProperty("reason_user")]
    private Dictionary<string, string>? reasonUser { get; set; }

    [JsonProperty("data")]
    private Dictionary<string, object>? data { get; set; }

    /// <summary>
    ///  This method selects an appropriate reason to use for creating ASP.NET Core
    ///  authorization decisions. Currently, it will select the search key if it
    ///  is present in the reason_user object, and if not it will select the key
    ///  which sorts first from reason_user. It will not consider data in
    ///  reason_admin.
    /// </summary>
    public string? GetReasonForDecision(string searchKey)
    {
        if (reasonUser == null)
        {
            return null;
        }

        if (reasonUser.TryGetValue(searchKey, out string reason))
        {
            return reason;
        }

        return reasonUser?.Keys.OrderBy(k => k).FirstOrDefault();
    }
}