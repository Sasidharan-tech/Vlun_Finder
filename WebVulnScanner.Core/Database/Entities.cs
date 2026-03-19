namespace WebVulnScanner.Core.Database;

public class ScanEntity
{
    public int Id { get; set; }
    public string TargetUrl { get; set; } = "";
    public DateTime ScanDate { get; set; }
    public int RiskScore { get; set; }
    public int PagesScanned { get; set; }
    public string ResultsJson { get; set; } = "";
}

public class ProxyLogEntity
{
    public int Id { get; set; }
    public string Method { get; set; } = "";
    public string Url { get; set; } = "";
    public string RawRequest { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public bool WasModified { get; set; }
}
