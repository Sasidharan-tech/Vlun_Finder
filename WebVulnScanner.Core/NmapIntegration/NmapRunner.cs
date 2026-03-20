using System.Diagnostics;
using System.Text;

namespace WebVulnScanner.Core.NmapIntegration;

public class NmapRunner
{
    private static readonly string[] NmapPaths =
    [
        @"C:\Program Files (x86)\Nmap\nmap.exe",
        @"C:\Program Files\Nmap\nmap.exe",
        @"C:\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap"
    ];

    public static string? FindNmap()
    {
        foreach (var path in NmapPaths)
        {
            if (File.Exists(path))
            {
                return path;
            }
        }

        try
        {
            var result = RunCommand("where", "nmap");
            if (string.IsNullOrWhiteSpace(result))
            {
                return null;
            }

            return result.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    public static bool IsNmapInstalled() => FindNmap() != null;

    public async Task<NmapResult> RunAsync(string arguments, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        var nmapPath = FindNmap() ?? throw new FileNotFoundException("Nmap not found. Install from https://nmap.org/download.html");

        var result = new NmapResult
        {
            Arguments = arguments,
            StartTime = DateTime.Now
        };

        var outputBuilder = new StringBuilder();
        var errorBuilder = new StringBuilder();

        var startInfo = new ProcessStartInfo
        {
            FileName = nmapPath,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8
        };

        using var process = new Process { StartInfo = startInfo };

        process.OutputDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is null)
            {
                return;
            }

            outputBuilder.AppendLine(eventArgs.Data);
            progress?.Report(eventArgs.Data);
        };

        process.ErrorDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is not null)
            {
                errorBuilder.AppendLine(eventArgs.Data);
            }
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var registration = cancellationToken.Register(() =>
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                }
            }
            catch
            {
            }
        });

        await Task.Run(process.WaitForExit, cancellationToken);

        result.RawOutput = outputBuilder.ToString();
        result.ErrorOutput = errorBuilder.ToString();
        result.ExitCode = process.ExitCode;
        result.EndTime = DateTime.Now;

        return result;
    }

    public Task<NmapResult> ScanSmbMs17010Async(string target, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        => RunAsync($"-p 445 --script smb-vuln-ms17-010,smb-protocols,smb2-security-mode -v {target}", progress, cancellationToken);

    public Task<NmapResult> ScanAllSmbVulnsAsync(string target, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        => RunAsync($"-p 139,445 --script \"smb-vuln-*\" -v {target}", progress, cancellationToken);

    public Task<NmapResult> ScanSmbProtocolsAsync(string target, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        => RunAsync($"-p 445 --script smb-protocols,smb2-security-mode,smb-security-mode {target}", progress, cancellationToken);

    public Task<NmapResult> ScanTopPortsAsync(string target, int topN = 100, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        => RunAsync($"--top-ports {topN} -sV {target}", progress, cancellationToken);

    private static string RunCommand(string fileName, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });

        return process?.StandardOutput.ReadToEnd() ?? string.Empty;
    }
}

public class NmapResult
{
    public string Arguments { get; set; } = string.Empty;
    public string RawOutput { get; set; } = string.Empty;
    public string ErrorOutput { get; set; } = string.Empty;
    public int ExitCode { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public TimeSpan Duration => EndTime - StartTime;
    public bool Success => ExitCode == 0;
}
