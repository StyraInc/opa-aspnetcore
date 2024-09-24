using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Styra.Opa.AspNetCore;
public class OpaResponseContext
{

    [JsonProperty("id")]
    public string? ID;

    [JsonProperty("reason_admin")]
    public Dictionary<string, string>? ReasonAdmin;

    [JsonProperty("reason_user")]
    public Dictionary<string, string>? ReasonUser;

    [JsonProperty("data")]
    public Dictionary<string, object>? Data;

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

        var firstKey = ReasonUser.Keys.OrderBy(k => k).FirstOrDefault();
        if (firstKey is null)
        {
            return null;
        }

        return ReasonUser.GetValueOrDefault(firstKey);
    }
}