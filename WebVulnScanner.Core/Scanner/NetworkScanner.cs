using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace WebVulnScanner.Core.Scanner;

public class NetworkScanner
{
    private CancellationTokenSource _cts = new();

    public event Action<ScanHost>? OnHostDiscovered;
    public event Action<PortResult>? OnPortFound;
    public event Action<string>? OnStatusUpdate;
    public event Action<double>? OnProgressUpdate;

    public async Task ScanAsync(NetworkScanOptions opts)
    {
        _cts = new CancellationTokenSource();
        var stopwatch = Stopwatch.StartNew();

        var targets = ResolveTargets(opts.Target);
        if (targets.Count == 0)
        {
            OnStatusUpdate?.Invoke("No valid targets resolved.");
            return;
        }

        OnStatusUpdate?.Invoke($"Scanning {targets.Count} host(s)...");

        var done = 0;
        foreach (var ip in targets)
        {
            if (_cts.Token.IsCancellationRequested)
            {
                break;
            }

            var alive = await IsHostAliveAsync(ip, opts);
            if (!alive && !opts.SkipPing)
            {
                done++;
                OnProgressUpdate?.Invoke((double)done / targets.Count * 100d);
                continue;
            }

            var host = new ScanHost { IpAddress = ip, Hostname = ip.ToString() };

            try
            {
                host.Hostname = (await Dns.GetHostEntryAsync(ip)).HostName;
            }
            catch
            {
            }

            if (opts.OsDetect)
            {
                host.OsGuess = GuessOsFromTtl(await GetTtlAsync(ip));
            }

            OnHostDiscovered?.Invoke(host);

            if (!opts.ScanType.Equals("Ping Only", StringComparison.OrdinalIgnoreCase))
            {
                var ports = ParsePortRange(opts.PortRange);
                await ScanPortsAsync(host, ports, opts);
            }

            done++;
            OnProgressUpdate?.Invoke((double)done / targets.Count * 100d);
        }

        stopwatch.Stop();
        OnStatusUpdate?.Invoke($"Done in {stopwatch.Elapsed.TotalSeconds:F1}s");
    }

    public void Stop()
    {
        _cts.Cancel();
        OnStatusUpdate?.Invoke("Scan stopped");
    }

    private async Task<bool> IsHostAliveAsync(IPAddress ip, NetworkScanOptions opts)
    {
        if (!opts.SkipPing)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, opts.Timeout);
                if (reply.Status == IPStatus.Success)
                {
                    return true;
                }
            }
            catch
            {
            }
        }

        foreach (var port in new[] { 80, 443, 22, 8080 })
        {
            if (await TcpConnectAsync(ip, port, opts.Timeout))
            {
                return true;
            }
        }

        return false;
    }

    private async Task ScanPortsAsync(ScanHost host, List<int> ports, NetworkScanOptions opts)
    {
        var maxConcurrency = Math.Clamp(opts.Threads, 5, 200);
        using var sem = new SemaphoreSlim(maxConcurrency);

        var tasks = ports.Select(async port =>
        {
            if (_cts.Token.IsCancellationRequested)
            {
                return;
            }

            await sem.WaitAsync(_cts.Token);
            try
            {
                var isOpen = await TcpConnectAsync(host.IpAddress, port, opts.Timeout);
                if (!isOpen)
                {
                    return;
                }

                var result = new PortResult
                {
                    Port = port,
                    Protocol = opts.ScanType.Contains("UDP", StringComparison.OrdinalIgnoreCase) ? "UDP" : "TCP",
                    State = "open",
                    Service = GetWellKnownService(port)
                };

                if (opts.ServiceDetect)
                {
                    var banner = await GrabBannerAsync(host.IpAddress, port, opts.Timeout);
                    result.Banner = banner;
                    result.Version = ParseVersion(banner, port);
                    result.Details = string.IsNullOrWhiteSpace(banner) ? "No banner" : banner;
                }

                if (opts.VulnCheck)
                {
                    result.Risk = CheckKnownVulns(port, result.Service, result.Version);
                }

                host.Ports.Add(result);
                OnPortFound?.Invoke(result);
            }
            catch
            {
            }
            finally
            {
                sem.Release();
            }
        });

        await Task.WhenAll(tasks);
    }

    private static async Task<bool> TcpConnectAsync(IPAddress ip, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            using var timeoutCts = new CancellationTokenSource(timeoutMs);
            await client.ConnectAsync(ip, port, timeoutCts.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string> GrabBannerAsync(IPAddress ip, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            using var connectCts = new CancellationTokenSource(timeoutMs);
            await client.ConnectAsync(ip, port, connectCts.Token);

            using var stream = client.GetStream();
            if (port is 80 or 8080 or 8000)
            {
                var req = $"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n";
                var bytes = Encoding.ASCII.GetBytes(req);
                await stream.WriteAsync(bytes);
            }

            if (port is 443 or 8443)
            {
                return await GetTlsCertInfoAsync(ip, port, timeoutMs);
            }

            var buffer = new byte[512];
            using var readCts = new CancellationTokenSource(timeoutMs);
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), readCts.Token);
            if (read <= 0)
            {
                return string.Empty;
            }

            return Encoding.ASCII.GetString(buffer, 0, read).Trim();
        }
        catch
        {
            return string.Empty;
        }
    }

    private static async Task<string> GetTlsCertInfoAsync(IPAddress ip, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            using var connectCts = new CancellationTokenSource(timeoutMs);
            await client.ConnectAsync(ip, port, connectCts.Token);

            using var ssl = new System.Net.Security.SslStream(client.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(ip.ToString());

            var cert = ssl.RemoteCertificate;
            return cert is null
                ? "TLS (no cert)"
                : $"TLS CN={cert.Subject} Expires={cert.GetExpirationDateString()}";
        }
        catch (Exception ex)
        {
            return $"TLS error: {ex.Message}";
        }
    }

    private static int GetTtlDefault(NetworkScanOptions opts) => opts.Timeout <= 0 ? 1000 : opts.Timeout;

    private static async Task<int> GetTtlAsync(IPAddress ip)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, 1000);
            return reply.Options?.Ttl ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static string GuessOsFromTtl(int ttl)
    {
        return ttl switch
        {
            <= 0 => "Unknown",
            <= 64 => "Linux / Android",
            <= 128 => "Windows",
            <= 255 => "Cisco / Network device",
            _ => "Unknown"
        };
    }

    private static string ParseVersion(string banner, int port)
    {
        if (string.IsNullOrWhiteSpace(banner))
        {
            return string.Empty;
        }

        var firstLine = banner.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";
        if (port is 80 or 443 or 8080 or 8443)
        {
            var serverMatch = Regex.Match(banner, @"Server:\s*(.+)", RegexOptions.IgnoreCase);
            if (serverMatch.Success)
            {
                return serverMatch.Groups[1].Value.Trim();
            }
        }

        return firstLine.Length > 160 ? firstLine[..160] : firstLine;
    }

    private static string CheckKnownVulns(int port, string service, string version)
    {
        var info = PortVulnerabilityDatabase.GetInfo(port);

        // Version-based checks override port-based for known EOL/vulnerable versions
        if (!string.IsNullOrEmpty(version))
        {
            if (version.Contains("OpenSSH 7.") || version.Contains("OpenSSH 6.") || version.Contains("OpenSSH 5."))
                return "High";

            if (version.Contains("Apache/2.2") || version.Contains("Apache/2.0") || version.Contains("Apache/1."))
                return "Critical";

            if (version.Contains("IIS/6") || version.Contains("IIS/5"))
                return "Critical";

            if (version.Contains("nginx/1.1") || version.Contains("nginx/1.0") || version.Contains("nginx/0."))
                return "High";

            if (version.Contains("PHP/5.") || version.Contains("PHP/4.") || version.Contains("PHP/3."))
                return "Critical";

            if (version.Contains("PHP/7.0") || version.Contains("PHP/7.1") || version.Contains("PHP/7.2"))
                return "High";

            if (version.Contains("OpenSSL/1.0") || version.Contains("OpenSSL/0.") || version.Contains("OpenSSL/3.0.0"))
                return "Critical";
        }

        return info.RiskLevel.Equals("Info", StringComparison.OrdinalIgnoreCase) ? "OK" : info.RiskLevel;
    }

    private static List<int> ParsePortRange(string range)
    {
        if (string.IsNullOrWhiteSpace(range))
        {
            return Top100Ports;
        }

        var input = range.Trim().ToLowerInvariant();
        if (input == "top100") return Top100Ports;
        if (input == "top1000") return Top1000Ports;

        var ports = new HashSet<int>();
        foreach (var part in input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Contains('-'))
            {
                var bounds = part.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (bounds.Length != 2) continue;
                if (!int.TryParse(bounds[0], out var start)) continue;
                if (!int.TryParse(bounds[1], out var end)) continue;

                if (start > end)
                {
                    (start, end) = (end, start);
                }

                start = Math.Clamp(start, 1, 65535);
                end = Math.Clamp(end, 1, 65535);

                for (var p = start; p <= end; p++)
                {
                    ports.Add(p);
                }
            }
            else if (int.TryParse(part, out var single))
            {
                if (single is >= 1 and <= 65535)
                {
                    ports.Add(single);
                }
            }
        }

        return ports.Count == 0 ? Top100Ports : ports.OrderBy(p => p).ToList();
    }

    private static List<IPAddress> ResolveTargets(string target)
    {
        var list = new List<IPAddress>();
        if (string.IsNullOrWhiteSpace(target))
        {
            return list;
        }

        if (target.Contains('/'))
        {
            var parts = target.Split('/');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var baseIp) && int.TryParse(parts[1], out var prefix))
            {
                prefix = Math.Clamp(prefix, 0, 32);
                var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                var baseInt = IpToUint(baseIp) & mask;
                var count = (uint)(1L << (32 - prefix));

                for (uint i = 1; i < count - 1; i++)
                {
                    list.Add(UintToIp(baseInt + i));
                }

                return list;
            }
        }

        if (target.Contains('-') && !target.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            var parts = target.Split('-');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var baseIp) && uint.TryParse(parts[1], out var hostCount))
            {
                var start = IpToUint(baseIp);
                var end = start + hostCount - 1;
                for (var i = start; i <= end; i++)
                {
                    list.Add(UintToIp(i));
                }

                return list;
            }
        }

        if (IPAddress.TryParse(target, out var singleIp))
        {
            list.Add(singleIp);
            return list;
        }

        try
        {
            var addresses = Dns.GetHostAddresses(target);
            list.AddRange(addresses.Where(ip => ip.AddressFamily == AddressFamily.InterNetwork));
        }
        catch
        {
        }

        return list;
    }

    private static uint IpToUint(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static IPAddress UintToIp(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return new IPAddress(bytes);
    }

    private static string GetWellKnownService(int port)
    {
        return port switch
        {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            6379 => "Redis",
            8080 => "HTTP-Alt",
            8443 => "HTTPS-Alt",
            9200 => "Elasticsearch",
            27017 => "MongoDB",
            _ => $"port/{port}"
        };
    }

    private static readonly List<int> Top100Ports =
    [
        21,22,23,25,53,80,110,111,135,139,143,194,443,445,465,
        587,993,995,1080,1194,1433,1521,1723,2082,2083,2086,2087,
        2095,2096,2181,2375,2376,3000,3306,3389,4443,4848,5000,
        5432,5672,5900,6379,6443,7001,7474,7547,8000,8080,8081,
        8082,8083,8088,8090,8161,8443,8444,8500,8888,9000,9001,
        9042,9092,9200,9300,10000,11211,15672,27017,28017,50000
    ];

    private static readonly List<int> Top1000Ports = Enumerable.Range(1, 1000).ToList();
}

public class ScanHost
{
    public IPAddress IpAddress { get; set; } = IPAddress.None;
    public string Hostname { get; set; } = "";
    public string OsGuess { get; set; } = "Unknown";
    public string MacAddress { get; set; } = "";
    public List<PortResult> Ports { get; set; } = [];
    public bool IsAlive => Ports.Any();
    public int OpenCount => Ports.Count(p => p.State == "open");
    public string RiskLevel => Ports.Any(p => p.Risk != "OK") ? "VULNERABLE" : "OK";
}

public class PortResult
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string State { get; set; } = "closed";
    public string Service { get; set; } = "";
    public string Version { get; set; } = "";
    public string Banner { get; set; } = "";
    public string Risk { get; set; } = "OK";
    public string Details { get; set; } = "";
}

public class NetworkScanOptions
{
    public string Target { get; set; } = "";
    public string PortRange { get; set; } = "top100";
    public string ScanType { get; set; } = "TCP Connect";
    public bool SkipPing { get; set; }
    public bool ServiceDetect { get; set; } = true;
    public bool OsDetect { get; set; }
    public bool VulnCheck { get; set; }
    public int Timeout { get; set; } = 1000;
    public int Threads { get; set; } = 50;
}
