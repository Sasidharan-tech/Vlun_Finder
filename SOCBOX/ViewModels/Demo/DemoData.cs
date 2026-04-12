using System.Collections.Generic;

namespace SOCBOX.ViewModels.Demo
{
    public static class DemoData
    {
        public static List<string> TerminalLogs => new List<string>
        {
            "[12:00:01] > Scan started...",
            "[12:00:02] > Target: [not set]",
            "[12:00:03] > Scanning ports...",
            "[12:00:05] > Vulnerability found: CVE-2023-1234",
            "[12:00:06] > Scan complete."
        };

        public static List<Vulnerability> Vulnerabilities => new List<Vulnerability>
        {
            new Vulnerability { Name = "CVE-2023-1234", Severity = "High", Description = "Remote code execution.", Status = "Open" },
            new Vulnerability { Name = "CVE-2022-5678", Severity = "Medium", Description = "SQL Injection.", Status = "Mitigated" },
            new Vulnerability { Name = "CVE-2021-9999", Severity = "Low", Description = "Information disclosure.", Status = "Open" }
        };
    }

    public class Vulnerability
    {
        public string Name { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string Status { get; set; }
    }
}
