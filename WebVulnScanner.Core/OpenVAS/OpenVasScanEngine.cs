namespace WebVulnScanner.Core.OpenVAS;

public class ScanEngineOptions
{
    public OpenVasSettings Connection { get; set; } = new();
    public string Target { get; set; } = string.Empty;
    public string TaskName { get; set; } = "VulnFinder Scan";
    public string ScanProfile { get; set; } = "Full and fast";
    public int PollIntervalSec { get; set; } = 5;
}

public class ScanProgress
{
    public string Message { get; set; } = string.Empty;
    public int Percent { get; set; }
    public string Status { get; set; } = string.Empty;
}

public class OpenVasScanEngine
{
    private CancellationTokenSource? _cts;

    public event Action<ScanProgress>? OnProgress;
    public event Action<List<OpenVasResult>>? OnComplete;
    public event Action<string>? OnLog;
    public event Action<Exception>? OnError;

    public bool IsRunning { get; private set; }

    public async Task RunScanAsync(ScanEngineOptions options)
    {
        _cts = new CancellationTokenSource();
        IsRunning = true;

        var client = new OpenVasClient(options.Connection);
        client.OnLog += msg => OnLog?.Invoke(msg);

        string? targetId = null;
        string? taskId = null;

        try
        {
            Report("Connecting to OpenVAS...", 2, "Connecting");
            await client.ConnectAsync(_cts.Token);

            Report("Loading scan profiles...", 5, "Configuring");
            var configs = await client.GetScanConfigsAsync(_cts.Token);
            var configId = ResolveConfigId(configs, options.ScanProfile);
            OnLog?.Invoke($"Using scan profile: {options.ScanProfile} ({configId})");

            Report($"Creating target: {options.Target}...", 10, "Preparing");
            targetId = await client.CreateTargetAsync($"VF_{DateTime.Now:yyyyMMddHHmm}", options.Target, _cts.Token);

            Report("Starting scan...", 15, "Running");
            var scan = await client.CreateAndStartScanAsync(targetId, configId, options.TaskName, _cts.Token);
            taskId = scan.TaskId;

            await PollScanProgress(client, scan, options, _cts.Token);

            Report("Fetching results...", 95, "Analysing");
            var results = await client.GetResultsAsync(scan.ReportId, _cts.Token);

            Report($"Scan complete — {results.Count} findings", 100, "Done");
            OnComplete?.Invoke(results);
        }
        catch (OperationCanceledException)
        {
            Report("Scan cancelled.", 0, "Cancelled");
            OnLog?.Invoke("Scan was stopped by user.");
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"ERROR: {ex.Message}");
            OnError?.Invoke(ex);
        }
        finally
        {
            if (taskId != null || targetId != null)
            {
                try
                {
                    await client.CleanupAsync(taskId ?? string.Empty, targetId ?? string.Empty);
                }
                catch
                {
                }
            }

            client.Dispose();
            IsRunning = false;
        }
    }

    private async Task PollScanProgress(OpenVasClient client, OpenVasScan scan, ScanEngineOptions options, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(options.PollIntervalSec * 1000, ct);

            var (status, percent) = await client.GetTaskStatusAsync(scan.TaskId, ct);
            scan.Status = status;
            scan.Progress = percent;

            var uiPercent = 15 + (int)(percent * 0.80);
            Report($"Scanning... {percent}%  ({status})", uiPercent, status);
            OnLog?.Invoke($"Task {scan.TaskId}: {status} {percent}%");

            if (status is "Done" or "Stopped" or "Interrupted")
            {
                scan.EndTime = DateTime.Now;
                break;
            }
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
    }

    private static string ResolveConfigId(List<(string Id, string Name)> configs, string profileName)
    {
        var exact = configs.FirstOrDefault(c => c.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(exact.Id))
        {
            return exact.Id;
        }

        var contains = configs.FirstOrDefault(c => c.Name.Contains(profileName, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(contains.Id))
        {
            return contains.Id;
        }

        return configs.Count > 0
            ? configs[0].Id
            : "daba56c8-73ec-11df-a475-002264764cea";
    }

    private void Report(string msg, int pct, string status)
    {
        OnProgress?.Invoke(new ScanProgress
        {
            Message = msg,
            Percent = pct,
            Status = status
        });
    }
}