using System.Net;

namespace WebVulnScanner.Core.Scanner;

public class HeaderFinding
{
    public string Header { get; set; } = "";
    public bool Present { get; set; }
    public string Value { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Description { get; set; } = "";
    public string Risk { get; set; } = "";
}

public class SecurityHeaderAnalyzer
{
    private static readonly Dictionary<string, string> RequiredHeaders = new()
    {
        ["Content-Security-Policy"] = "Prevents XSS by controlling resource loading",
        ["Strict-Transport-Security"] = "Forces HTTPS and prevents downgrade attacks",
        ["X-Frame-Options"] = "Prevents clickjacking via iframes",
        ["X-Content-Type-Options"] = "Prevents MIME-sniffing attacks",
        ["Referrer-Policy"] = "Controls referrer information leakage",
        ["Permissions-Policy"] = "Restricts browser feature access",
        ["X-XSS-Protection"] = "Legacy XSS filter",
        ["Cross-Origin-Opener-Policy"] = "Isolates browsing context",
        ["Cross-Origin-Resource-Policy"] = "Controls cross-origin resource reads"
    };

    public async Task<List<HeaderFinding>> AnalyzeAsync(string url)
    {
        var findings = new List<HeaderFinding>();

        using var client = new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("WebVulnScanner/1.0");
        using var response = await client.GetAsync(url);

        foreach (var (header, description) in RequiredHeaders)
        {
            var inResponseHeaders = response.Headers.TryGetValues(header, out var values);
            var inContentHeaders = response.Content.Headers.TryGetValues(header, out var contentValues);
            var present = inResponseHeaders || inContentHeaders;

            var value = inResponseHeaders
                ? string.Join(", ", values!)
                : inContentHeaders
                    ? string.Join(", ", contentValues!)
                    : "MISSING";

            findings.Add(new HeaderFinding
            {
                Header = header,
                Present = present,
                Value = value,
                Severity = present ? "Info" : "Medium",
                Description = description,
                Risk = present ? "OK" : $"Missing {header} may expose the site to attacks"
            });
        }

        if (response.Headers.TryGetValues("Access-Control-Allow-Origin", out var corsValues))
        {
            var val = corsValues.FirstOrDefault() ?? "";
            if (val == "*")
            {
                findings.Add(new HeaderFinding
                {
                    Header = "CORS",
                    Severity = "High",
                    Value = val,
                    Description = "Cross-origin policy",
                    Risk = "Wildcard CORS allows any origin to read responses"
                });
            }
        }

        if (response.Headers.TryGetValues("Set-Cookie", out var cookieValues))
        {
            foreach (var cookie in cookieValues)
            {
                if (!cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new HeaderFinding
                    {
                        Header = "Cookie",
                        Severity = "Medium",
                        Value = cookie,
                        Description = "Cookie flags",
                        Risk = "Cookie missing HttpOnly flag"
                    });
                }

                if (!cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new HeaderFinding
                    {
                        Header = "Cookie",
                        Severity = "Medium",
                        Value = cookie,
                        Description = "Cookie flags",
                        Risk = "Cookie missing Secure flag"
                    });
                }
            }
        }

        return findings;
    }
}
