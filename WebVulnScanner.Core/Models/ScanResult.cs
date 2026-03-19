namespace WebVulnScanner.Core.Models;

public class ScanResult
{
    public string TargetUrl { get; set; } = "";
    public int PagesScanned { get; set; }
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
    public int RiskScore { get; set; }
    public DateTime ScanDate { get; set; }
}