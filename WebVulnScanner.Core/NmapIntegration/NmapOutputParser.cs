using System.Text.RegularExpressions;

namespace WebVulnScanner.Core.NmapIntegration;

public enum SmbVulnResult
{
    Vulnerable,
    Safe,
    Inconclusive,
    Unknown
}

public static class NmapOutputParser
{
    public static SmbVulnResult ParseMs17010Result(string nmapOutput)
    {
        if (string.IsNullOrWhiteSpace(nmapOutput))
        {
            return SmbVulnResult.Unknown;
        }

        if (nmapOutput.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase) ||
            (nmapOutput.Contains("MS17-010", StringComparison.OrdinalIgnoreCase) &&
             nmapOutput.Contains("LIKELY", StringComparison.OrdinalIgnoreCase)))
        {
            return SmbVulnResult.Vulnerable;
        }

        if (nmapOutput.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase) ||
            nmapOutput.Contains("SMBv1: disabled", StringComparison.OrdinalIgnoreCase))
        {
            return SmbVulnResult.Safe;
        }

        if (Regex.IsMatch(nmapOutput, @"445/tcp\s+open", RegexOptions.IgnoreCase) &&
            !nmapOutput.Contains("smb-vuln-ms17-010:", StringComparison.OrdinalIgnoreCase))
        {
            return SmbVulnResult.Inconclusive;
        }

        return SmbVulnResult.Unknown;
    }

    public static string GetResultReason(SmbVulnResult result)
    {
        return result switch
        {
            SmbVulnResult.Vulnerable => "Host appears vulnerable to MS17-010. Patch immediately and disable SMBv1.",
            SmbVulnResult.Safe => "Host appears safe from MS17-010 (patched or SMBv1 disabled).",
            SmbVulnResult.Inconclusive => "Port 445 is open but script output is inconclusive. Run smb-protocols and smb-security-mode checks.",
            _ => "Unable to determine result from output."
        };
    }

    public static string GetResultColor(SmbVulnResult result)
    {
        return result switch
        {
            SmbVulnResult.Vulnerable => "#DC2626",
            SmbVulnResult.Safe => "#16A34A",
            SmbVulnResult.Inconclusive => "#D97706",
            _ => "#64748B"
        };
    }
}
