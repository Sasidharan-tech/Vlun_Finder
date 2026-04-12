using WebVulnScanner.Core.Models;

namespace WebVulnScanner.Desktop.ViewModels;

public class ScannerViewModel
{
    public string TargetUrl { get; set; } = string.Empty;
    public bool IsDeepScan { get; set; }
    public List<Vulnerability> Findings { get; set; } = new();
}
