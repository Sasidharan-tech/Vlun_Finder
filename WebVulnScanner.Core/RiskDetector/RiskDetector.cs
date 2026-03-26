using System.Text.RegularExpressions;

namespace WebVulnScanner.Core.RiskDetector;

public enum RiskLevel
{
    Safe,
    Low,
    Medium,
    High,
    Critical
}

public class RiskFinding
{
    public RiskLevel Level { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public string FixSummary { get; set; } = string.Empty;

    public string LevelText => Level.ToString().ToUpperInvariant();
}

public class RiskReport
{
    public string Target { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public bool HostUp { get; set; }
    public RiskLevel OverallRisk { get; set; } = RiskLevel.Safe;
    public string Verdict { get; set; } = string.Empty;
    public string VerdictDetail { get; set; } = string.Empty;
    public List<RiskFinding> Findings { get; set; } = [];
    public List<string> SafePoints { get; set; } = [];
    public List<string> NextSteps { get; set; } = [];

    public bool Ms17010Vuln { get; set; }

    public string VerdictColor => OverallRisk switch
    {
        RiskLevel.Critical => "#DC2626",
        RiskLevel.High => "#EA580C",
        RiskLevel.Medium => "#D97706",
        RiskLevel.Low => "#2563EB",
        _ => "#16A34A"
    };

    public string VerdictBg => OverallRisk switch
    {
        RiskLevel.Critical => "#1A0505",
        RiskLevel.High => "#1A0A05",
        RiskLevel.Medium => "#1A1005",
        RiskLevel.Low => "#05101A",
        _ => "#051A0A"
    };

    public string VerdictIcon => OverallRisk switch
    {
        RiskLevel.Critical => "CRITICAL",
        RiskLevel.High => "HIGH RISK",
        RiskLevel.Medium => "MEDIUM RISK",
        RiskLevel.Low => "LOW RISK",
        _ => "SAFE"
    };

    public int CriticalCount => Findings.Count(f => f.Level == RiskLevel.Critical);
    public int HighCount => Findings.Count(f => f.Level == RiskLevel.High);
    public int MediumCount => Findings.Count(f => f.Level == RiskLevel.Medium);
}

public static class RiskDetector
{
    public static RiskReport Analyze(string nmapOutput)
    {
        var report = new RiskReport();

        if (string.IsNullOrWhiteSpace(nmapOutput))
        {
            report.Verdict = "NO DATA";
            report.VerdictDetail = "No scan output to analyze.";
            return report;
        }

        CheckHostStatus(nmapOutput, report);

        if (!report.HostUp)
        {
            report.OverallRisk = RiskLevel.Safe;
            report.Verdict = "HOST DOWN";
            report.VerdictDetail = "Host not responding to ping. It may be offline or blocking ICMP.";
            if (!string.IsNullOrWhiteSpace(report.IpAddress))
            {
                report.NextSteps.Add($"nmap -Pn -p 445 --script smb-vuln-ms17-010 {report.IpAddress}");
                report.NextSteps.Add($"ping {report.IpAddress}");
            }
            return report;
        }

        CheckVulnerabilities(nmapOutput, report);
        CheckDangerousPorts(nmapOutput, report);
        CheckServiceVersions(nmapOutput, report);
        CheckTlsIssues(nmapOutput, report);
        CalculateFinalVerdict(report);

        return report;
    }

    private static void CheckHostStatus(string output, RiskReport report)
    {
        var ipMatch = Regex.Match(output, @"scan report for .+?(\d+\.\d+\.\d+\.\d+)", RegexOptions.IgnoreCase);
        if (ipMatch.Success)
        {
            report.IpAddress = ipMatch.Groups[1].Value;
        }

        var hostMatch = Regex.Match(output, @"Nmap scan report for (.+)", RegexOptions.IgnoreCase);
        if (hostMatch.Success)
        {
            report.Target = hostMatch.Groups[1].Value.Trim();
        }

        report.HostUp = output.Contains("Host is up", StringComparison.OrdinalIgnoreCase)
            || Regex.IsMatch(output, @"\d+/(tcp|udp)\s+open", RegexOptions.IgnoreCase);

        if (output.Contains("host down", StringComparison.OrdinalIgnoreCase)
            || output.Contains("0 hosts up", StringComparison.OrdinalIgnoreCase)
            || output.Contains("Host seems down", StringComparison.OrdinalIgnoreCase))
        {
            report.HostUp = false;
        }
    }

    private static void CheckVulnerabilities(string output, RiskReport report)
    {
        if (output.Contains("smb-vuln-ms17-010", StringComparison.OrdinalIgnoreCase))
        {
            if (output.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase)
                && !output.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase))
            {
                report.Ms17010Vuln = true;
                report.Findings.Add(new RiskFinding
                {
                    Level = RiskLevel.Critical,
                    Category = "Vulnerability",
                    Title = "MS17-010 EternalBlue vulnerable",
                    Detail = "Host appears vulnerable to EternalBlue ransomware-style exploitation.",
                    FixSummary = "Apply MS17-010 related patches and disable SMBv1 immediately."
                });
            }
            else if (output.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase)
                || output.Contains("APPEARS TO BE SAFE", StringComparison.OrdinalIgnoreCase))
            {
                report.SafePoints.Add("MS17-010: not vulnerable");
            }
            else
            {
                report.Findings.Add(new RiskFinding
                {
                    Level = RiskLevel.Medium,
                    Category = "Vulnerability",
                    Title = "MS17-010 inconclusive",
                    Detail = "Script ran without a clear vulnerable/safe verdict.",
                    FixSummary = "Re-run with -Pn and smb-protocols to confirm SMB exposure."
                });
            }
        }

        if (output.Contains("ssl-heartbleed", StringComparison.OrdinalIgnoreCase)
            && output.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase))
        {
            report.Findings.Add(new RiskFinding
            {
                Level = RiskLevel.Critical,
                Category = "Vulnerability",
                Title = "Heartbleed detected",
                Detail = "TLS service appears vulnerable to memory disclosure.",
                FixSummary = "Upgrade OpenSSL and replace impacted certificates."
            });
        }
    }

    private static void CheckDangerousPorts(string output, RiskReport report)
    {
        var dangerousPorts = new Dictionary<int, (RiskLevel level, string name, string detail, string fix)>
        {
            [23] = (RiskLevel.Critical, "Telnet", "Unencrypted remote access service exposed.", "Disable Telnet and use SSH."),
            [21] = (RiskLevel.High, "FTP", "Unencrypted file transfer service exposed.", "Move to SFTP/FTPS and disable anonymous access."),
            [3389] = (RiskLevel.High, "RDP", "Remote Desktop exposed and often brute-forced.", "Restrict with firewall/VPN and enforce NLA."),
            [4444] = (RiskLevel.Critical, "Potential C2 shell", "Port often used for reverse shells.", "Investigate for compromise and isolate host."),
            [6379] = (RiskLevel.Critical, "Redis", "Commonly exposed without auth.", "Bind localhost and require authentication."),
            [9200] = (RiskLevel.Critical, "Elasticsearch", "Data exposure risk if unauthenticated.", "Enable auth and restrict network access."),
            [27017] = (RiskLevel.Critical, "MongoDB", "Database exposure risk.", "Enable auth and block public access."),
            [2375] = (RiskLevel.Critical, "Docker API", "Unauthenticated Docker daemon exposure.", "Close 2375 and use secured socket/TLS."),
            [1433] = (RiskLevel.High, "MSSQL", "Database port exposed.", "Restrict access and harden SQL authentication."),
            [3306] = (RiskLevel.High, "MySQL", "Database port exposed.", "Restrict access and enforce strong credentials."),
            [5432] = (RiskLevel.High, "PostgreSQL", "Database port exposed.", "Restrict access via firewall and pg_hba hardening.")
        };

        foreach (var (port, info) in dangerousPorts)
        {
            if (Regex.IsMatch(output, $@"{port}/tcp\s+open", RegexOptions.IgnoreCase))
            {
                report.Findings.Add(new RiskFinding
                {
                    Level = info.level,
                    Category = "Open Port",
                    Title = $"Port {port} open ({info.name})",
                    Detail = info.detail,
                    FixSummary = info.fix
                });
            }
        }
    }

    private static void CheckServiceVersions(string output, RiskReport report)
    {
        var checks = new List<(string pattern, RiskLevel level, string title, string fix)>
        {
            (@"Apache[/ ]2\.2\.", RiskLevel.High, "Apache 2.2.x is end-of-life", "Upgrade Apache to a supported 2.4.x release."),
            (@"PHP[/ ]([4-6]\.|7\.[0-2]\.)", RiskLevel.Critical, "Old PHP version detected", "Upgrade PHP to a supported modern version."),
            (@"OpenSSH[_ ]([1-6]\.|7\.[0-3])", RiskLevel.High, "Old OpenSSH version detected", "Upgrade OpenSSH to latest stable."),
            (@"vsftpd 2\.3\.4", RiskLevel.Critical, "vsftpd 2.3.4 backdoor risk", "Upgrade vsftpd and investigate host integrity.")
        };

        foreach (var (pattern, level, title, fix) in checks)
        {
            if (Regex.IsMatch(output, pattern, RegexOptions.IgnoreCase))
            {
                report.Findings.Add(new RiskFinding
                {
                    Level = level,
                    Category = "Version",
                    Title = title,
                    Detail = "Outdated software may have known public exploits.",
                    FixSummary = fix
                });
            }
        }
    }

    private static void CheckTlsIssues(string output, RiskReport report)
    {
        if (output.Contains("TLSv1.0", StringComparison.OrdinalIgnoreCase)
            || output.Contains("SSLv3", StringComparison.OrdinalIgnoreCase))
        {
            report.Findings.Add(new RiskFinding
            {
                Level = RiskLevel.High,
                Category = "Configuration",
                Title = "Legacy TLS/SSL protocol enabled",
                Detail = "Old TLS/SSL protocols are vulnerable to downgrade and crypto attacks.",
                FixSummary = "Disable SSLv3/TLS1.0/TLS1.1 and keep TLS1.2+ only."
            });
        }

        if (output.Contains("self-signed", StringComparison.OrdinalIgnoreCase))
        {
            report.Findings.Add(new RiskFinding
            {
                Level = RiskLevel.Medium,
                Category = "Configuration",
                Title = "Self-signed certificate detected",
                Detail = "Self-signed certificates increase trust and MITM risk.",
                FixSummary = "Use a trusted CA-issued certificate."
            });
        }
    }

    private static void CalculateFinalVerdict(RiskReport report)
    {
        if (report.Findings.Count == 0)
        {
            report.OverallRisk = RiskLevel.Safe;
            report.Verdict = "SAFE";
            report.VerdictDetail = "No high-risk findings detected from the available Nmap output.";
            if (report.SafePoints.Count == 0)
            {
                report.SafePoints.Add("No obvious exposed risk indicators found.");
            }
            return;
        }

        report.OverallRisk = report.Findings.Max(f => f.Level);
        report.Verdict = report.OverallRisk >= RiskLevel.High ? "NOT SAFE" : "CAUTION";

        var summaryParts = new List<string>();
        if (report.CriticalCount > 0)
        {
            summaryParts.Add($"{report.CriticalCount} critical");
        }

        if (report.HighCount > 0)
        {
            summaryParts.Add($"{report.HighCount} high");
        }

        if (report.MediumCount > 0)
        {
            summaryParts.Add($"{report.MediumCount} medium");
        }

        report.VerdictDetail = $"Found {string.Join(", ", summaryParts)} risk finding(s). Highest: {report.OverallRisk.ToString().ToUpperInvariant()}.";

        foreach (var finding in report.Findings.OrderByDescending(f => f.Level).Take(5))
        {
            report.NextSteps.Add($"[{finding.LevelText}] {finding.FixSummary}");
        }

        if (report.NextSteps.Count == 0 && !string.IsNullOrWhiteSpace(report.IpAddress))
        {
            report.NextSteps.Add($"nmap -sV --top-ports 1000 {report.IpAddress}");
        }
    }
}
