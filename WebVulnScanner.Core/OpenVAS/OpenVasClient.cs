using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;

namespace WebVulnScanner.Core.OpenVAS;

public class OpenVasSettings
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 9390;
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = "admin";
    public bool AcceptAllCerts { get; set; } = true;
}

public class OpenVasScan
{
    public string TaskId { get; set; } = string.Empty;
    public string TaskName { get; set; } = string.Empty;
    public string TargetId { get; set; } = string.Empty;
    public string ReportId { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public int Progress { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
}

public class OpenVasResult
{
    public string ResultId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Port { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public double CvssScore { get; set; }
    public string CveId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Solution { get; set; } = string.Empty;
    public string FamilyName { get; set; } = string.Empty;
    public string NvtOid { get; set; } = string.Empty;

    public string SeverityUpper => Severity.ToUpperInvariant();

    public string SeverityColor => Severity.ToLowerInvariant() switch
    {
        "critical" => "#DC2626",
        "high" => "#EA580C",
        "medium" => "#D97706",
        "low" => "#2563EB",
        _ => "#475569"
    };

    public string CvssDisplay => CvssScore > 0 ? CvssScore.ToString("F1") : "—";
}

public class OpenVasClient : IDisposable
{
    private readonly OpenVasSettings _settings;
    private TcpClient? _tcp;
    private SslStream? _ssl;
    private bool _authenticated;

    public event Action<string>? OnLog;

    public OpenVasClient(OpenVasSettings settings)
    {
        _settings = settings;
    }

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        Log($"Connecting to {_settings.Host}:{_settings.Port}...");

        _tcp = new TcpClient();
        await _tcp.ConnectAsync(_settings.Host, _settings.Port, ct);

        _ssl = new SslStream(
            _tcp.GetStream(),
            false,
            _settings.AcceptAllCerts ? (_, _, _, _) => true : null);

        await _ssl.AuthenticateAsClientAsync(_settings.Host);
        Log("TLS connection established.");

        var banner = await ReadResponseAsync(ct);
        Log($"GVM version: {ExtractAttribute(banner, "get_protocol_version", "version")}");

        await AuthenticateAsync(ct);
    }

    private async Task AuthenticateAsync(CancellationToken ct)
    {
        Log($"Authenticating as '{_settings.Username}'...");

        var cmd = $"<authenticate><credentials><username>{Escape(_settings.Username)}</username><password>{Escape(_settings.Password)}</password></credentials></authenticate>";
        var response = await SendCommandAsync(cmd, ct);
        var status = ExtractAttribute(response, "authenticate_response", "status");

        if (status != "200")
        {
            throw new InvalidOperationException($"Authentication failed. Status: {status}. Check username/password.");
        }

        _authenticated = true;
        Log("Authenticated successfully.");
    }

    public async Task<string> CreateTargetAsync(string name, string hosts, CancellationToken ct = default)
    {
        EnsureAuth();
        Log($"Creating target: {hosts}");

        var cmd = $"<create_target><name>{Escape(name)}</name><hosts>{Escape(hosts)}</hosts><port_range>T:1-65535,U:1-500</port_range></create_target>";
        var response = await SendCommandAsync(cmd, ct);
        var id = ExtractAttribute(response, "create_target_response", "id");

        if (string.IsNullOrWhiteSpace(id))
        {
            throw new InvalidOperationException("OpenVAS did not return a target ID.");
        }

        Log($"Target created. ID: {id}");
        return id;
    }

    public async Task<List<(string Id, string Name)>> GetScanConfigsAsync(CancellationToken ct = default)
    {
        EnsureAuth();

        var response = await SendCommandAsync("<get_configs/>", ct);
        var doc = XDocument.Parse(response);
        var configs = new List<(string Id, string Name)>();

        foreach (var cfg in doc.Descendants("config"))
        {
            var id = cfg.Attribute("id")?.Value ?? string.Empty;
            var name = cfg.Element("name")?.Value ?? string.Empty;

            if (!string.IsNullOrWhiteSpace(id))
            {
                configs.Add((id, name));
            }
        }

        return configs;
    }

    public async Task<OpenVasScan> CreateAndStartScanAsync(string targetId, string scanConfigId, string taskName = "VulnFinder Scan", CancellationToken ct = default)
    {
        EnsureAuth();

        Log("Creating scan task...");
        var createCmd = $"<create_task><name>{Escape(taskName)}</name><config id=\"{Escape(scanConfigId)}\"/><target id=\"{Escape(targetId)}\"/></create_task>";
        var createResp = await SendCommandAsync(createCmd, ct);
        var taskId = ExtractAttribute(createResp, "create_task_response", "id");

        if (string.IsNullOrWhiteSpace(taskId))
        {
            throw new InvalidOperationException("OpenVAS did not return a task ID.");
        }

        Log($"Task created. ID: {taskId}");

        Log("Starting scan...");
        var startResp = await SendCommandAsync($"<start_task task_id=\"{Escape(taskId)}\"/>", ct);
        var reportId = ExtractElement(startResp, "report_id");
        Log($"Scan started. Report ID: {reportId}");

        return new OpenVasScan
        {
            TaskId = taskId,
            TaskName = taskName,
            TargetId = targetId,
            ReportId = reportId,
            Status = "Running",
            StartTime = DateTime.Now
        };
    }

    public async Task<(string Status, int Progress)> GetTaskStatusAsync(string taskId, CancellationToken ct = default)
    {
        EnsureAuth();

        var response = await SendCommandAsync($"<get_tasks task_id=\"{Escape(taskId)}\"/>", ct);
        var doc = XDocument.Parse(response);
        var task = doc.Descendants("task").FirstOrDefault();

        if (task == null)
        {
            return ("Unknown", 0);
        }

        var status = task.Element("status")?.Value ?? "Unknown";
        var progressStr = task.Element("progress")?.Value ?? "0";
        _ = int.TryParse(progressStr, out var progress);

        return (status, Math.Clamp(progress, 0, 100));
    }

    public async Task<List<OpenVasResult>> GetResultsAsync(string reportId, CancellationToken ct = default)
    {
        EnsureAuth();
        Log($"Fetching results from report {reportId}...");

        var cmd = $"<get_reports report_id=\"{Escape(reportId)}\" filter=\"apply_overrides=0 levels=hmlg rows=1000 min_qod=70 first=1 sort-reverse=severity\" ignore_pagination=\"1\" details=\"1\"/>";
        var response = await SendCommandAsync(cmd, ct);
        return ParseResults(response);
    }

    public async Task StopScanAsync(string taskId, CancellationToken ct = default)
    {
        EnsureAuth();
        await SendCommandAsync($"<stop_task task_id=\"{Escape(taskId)}\"/>", ct);
        Log("Scan stopped.");
    }

    public async Task CleanupAsync(string taskId, string targetId, CancellationToken ct = default)
    {
        EnsureAuth();

        try
        {
            if (!string.IsNullOrWhiteSpace(taskId))
            {
                await SendCommandAsync($"<delete_task task_id=\"{Escape(taskId)}\"/>", ct);
            }

            if (!string.IsNullOrWhiteSpace(targetId))
            {
                await SendCommandAsync($"<delete_target target_id=\"{Escape(targetId)}\"/>", ct);
            }
        }
        catch
        {
        }
    }

    private List<OpenVasResult> ParseResults(string xml)
    {
        var results = new List<OpenVasResult>();

        try
        {
            var doc = XDocument.Parse(xml);

            foreach (var result in doc.Descendants("result"))
            {
                var severityStr = result.Element("severity")?.Value ?? "0";
                _ = double.TryParse(severityStr, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var cvssScore);

                var nvt = result.Element("nvt");
                var description = result.Element("description")?.Value?.Trim() ?? string.Empty;

                var solution = nvt?.Element("solution")?.Value?.Trim()
                    ?? result.Element("solution")?.Value?.Trim()
                    ?? ExtractSolution(description);

                results.Add(new OpenVasResult
                {
                    ResultId = result.Attribute("id")?.Value ?? string.Empty,
                    Name = nvt?.Element("name")?.Value ?? result.Element("name")?.Value ?? string.Empty,
                    Host = result.Element("host")?.Value?.Trim() ?? string.Empty,
                    Port = result.Element("port")?.Value ?? string.Empty,
                    CvssScore = cvssScore,
                    Severity = CvssToSeverity(cvssScore),
                    CveId = nvt?.Element("cve")?.Value ?? string.Empty,
                    Description = description.Length > 800 ? description[..800] + "..." : description,
                    Solution = solution,
                    FamilyName = nvt?.Element("family")?.Value ?? string.Empty,
                    NvtOid = nvt?.Attribute("oid")?.Value ?? string.Empty
                });
            }
        }
        catch (Exception ex)
        {
            Log($"Parse error: {ex.Message}");
        }

        Log($"Parsed {results.Count} vulnerability findings.");
        return results;
    }

    private string CvssToSeverity(double score)
    {
        return score switch
        {
            >= 9.0 => "critical",
            >= 7.0 => "high",
            >= 4.0 => "medium",
            > 0 => "low",
            _ => "log"
        };
    }

    private string ExtractSolution(string description)
    {
        var index = description.IndexOf("Solution:", StringComparison.OrdinalIgnoreCase);
        if (index >= 0)
        {
            var solution = description[(index + 9)..].Trim();
            return solution.Length > 500 ? solution[..500] : solution;
        }

        return "Apply vendor patch or update. See CVE reference for details.";
    }

    private async Task<string> SendCommandAsync(string command, CancellationToken ct = default)
    {
        if (_ssl == null)
        {
            throw new InvalidOperationException("Not connected.");
        }

        var bytes = Encoding.UTF8.GetBytes(command);
        await _ssl.WriteAsync(bytes, ct);
        await _ssl.FlushAsync(ct);

        return await ReadResponseAsync(ct);
    }

    private async Task<string> ReadResponseAsync(CancellationToken ct = default)
    {
        if (_ssl == null)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        var buffer = new byte[8192];

        while (true)
        {
            var read = await _ssl.ReadAsync(buffer, ct);
            if (read == 0)
            {
                break;
            }

            sb.Append(Encoding.UTF8.GetString(buffer, 0, read));
            var text = sb.ToString().Trim();
            if (IsCompleteXml(text))
            {
                break;
            }
        }

        return sb.ToString();
    }

    private static bool IsCompleteXml(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        try
        {
            _ = XDocument.Parse(text);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ExtractAttribute(string xml, string element, string attr)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            return doc.Descendants(element).FirstOrDefault()?.Attribute(attr)?.Value ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ExtractElement(string xml, string element)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            return doc.Descendants(element).FirstOrDefault()?.Value ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal)
            .Replace("'", "&apos;", StringComparison.Ordinal);
    }

    private void EnsureAuth()
    {
        if (!_authenticated)
        {
            throw new InvalidOperationException("Not authenticated. Call ConnectAsync first.");
        }
    }

    private void Log(string msg)
    {
        OnLog?.Invoke($"[OpenVAS] {msg}");
    }

    public void Dispose()
    {
        _ssl?.Dispose();
        _tcp?.Dispose();
    }
}