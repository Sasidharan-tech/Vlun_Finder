namespace WebVulnScanner.Core.Models;

public class InterceptedRequest
{
    public string Method { get; set; } = "";
    public string Url { get; set; } = "";
    public string Host { get; set; } = "";
    public Dictionary<string, string> Headers { get; set; } = new();
    public string Body { get; set; } = "";
    public string RawRequest { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public bool Dropped { get; set; }
    public bool Modified { get; set; }
}