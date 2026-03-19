using WebVulnScanner.Core.Models;

namespace WebVulnScanner.Desktop.ViewModels;

public class ProxyViewModel
{
    public bool IsProxyRunning { get; set; }
    public bool IsInterceptEnabled { get; set; } = true;
    public int Port { get; set; } = 8080;
    public List<InterceptedRequest> Requests { get; set; } = new();
}
