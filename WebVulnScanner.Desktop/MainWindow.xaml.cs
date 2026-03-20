using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WebVulnScanner.Core.Database;
using WebVulnScanner.Core.Models;
using WebVulnScanner.Core.Proxy;
using WebVulnScanner.Core.Reports;
using WebVulnScanner.Core.NmapIntegration;
using WebVulnScanner.Core.Scanner;

namespace WebVulnScanner.Desktop;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private InterceptingProxyServer? _proxyServer;
    private ProxyRequestEntry? _selectedRequest;
    private NetworkScanner? _netScanner;
    private ScanHost? _selectedHost;
    private DateTime _networkScanStartedAt;
    private NmapRunner? _nmapRunner;
    private CancellationTokenSource? _nmapCancellation;
    private readonly ObservableCollection<NmapPortViewModel> _nmapPortItems = new();

    private readonly ObservableCollection<ProxyRequestEntry> _proxyRequests = new();
    private readonly ObservableCollection<ScanViewModel> _scans = new();
    private VulnerabilityScanner? _currentScanner;
    private ScanResult? _lastScanResult;

    public int TotalScans => _scans.Count;
    public int CriticalCount => _scans.Count(s => s.RiskScore >= 75);
    public int ProxyRequestCount => _proxyRequests.Count;
    public int ActiveScans { get; private set; }
    public ObservableCollection<ScanViewModel> RecentScans => _scans;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

        using var db = new AppDbContext();
        db.Database.EnsureCreated();

        gridProxy.ItemsSource = _proxyRequests;
        InitNmapScannerTab();
        LoadRecentScans();
        NotifyStatsChanged();
    }

    private void InitNmapScannerTab()
    {
        _nmapRunner = new NmapRunner();
        gridAdvNmapPorts.ItemsSource = _nmapPortItems;

        if (NmapRunner.IsNmapInstalled())
        {
            txtAdvNmapInstallStatus.Text = "Nmap: Found";
            borderAdvNmapStatus.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0F4418"));
            borderAdvNmapStatus.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#16A34A"));
            txtAdvNmapInstallStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
        }
        else
        {
            txtAdvNmapInstallStatus.Text = "Nmap: NOT INSTALLED";
            borderAdvNmapStatus.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#441414"));
            borderAdvNmapStatus.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DC2626"));
            txtAdvNmapInstallStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F87171"));
        }

        UpdateAdvNmapCommandPreview();
        ResetAdvancedNmapDetails();
    }

    private void CmbAdvNmapProfile_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateAdvNmapCommandPreview();
    }

    private void UpdateAdvNmapCommandPreview()
    {
        var target = string.IsNullOrWhiteSpace(txtAdvNmapTarget.Text) ? "127.0.0.1" : txtAdvNmapTarget.Text.Trim();
        var profile = cmbAdvNmapProfile.SelectedIndex;

        var args = profile switch
        {
            0 => $"-p 445 --script smb-vuln-ms17-010,smb-protocols,smb2-security-mode -v {target}",
            1 => $"-p 139,445 --script \"smb-vuln-*\" -v {target}",
            2 => $"-p 445 --script smb-protocols,smb2-security-mode,smb-security-mode {target}",
            3 => $"--top-ports 100 -sV {target}",
            4 => $"--top-ports 1000 -sV {target}",
            _ => $"-p 445 --script smb-vuln-ms17-010,smb-protocols,smb2-security-mode -v {target}"
        };

        txtAdvNmapCommand.Text = $"nmap {args}";
    }

    private async void BtnAdvNmapStart_Click(object sender, RoutedEventArgs e)
    {
        if (!NmapRunner.IsNmapInstalled())
        {
            MessageBox.Show("Nmap is not installed. Download from https://nmap.org/download.html", "Nmap", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        UpdateAdvNmapCommandPreview();
        btnAdvNmapStart.IsEnabled = false;
        btnAdvNmapStop.IsEnabled = true;
        progressAdvNmap.IsIndeterminate = true;
        txtAdvNmapStatus.Text = "Running...";
        txtAdvNmapRawOutput.Clear();
        _nmapPortItems.Clear();
        ResetAdvancedNmapDetails();

        _nmapRunner = new NmapRunner();
        _nmapCancellation = new CancellationTokenSource();

        var args = txtAdvNmapCommand.Text.StartsWith("nmap ", StringComparison.OrdinalIgnoreCase)
            ? txtAdvNmapCommand.Text[5..]
            : txtAdvNmapCommand.Text;

        try
        {
            var progress = new Progress<string>(line =>
            {
                Dispatcher.Invoke(() =>
                {
                    txtAdvNmapRawOutput.AppendText(line + Environment.NewLine);
                    txtAdvNmapRawOutput.ScrollToEnd();
                });
            });

            var result = await _nmapRunner.RunAsync(args, progress, _nmapCancellation.Token);
            txtAdvNmapStatus.Text = result.Success ? "Completed" : "Completed with errors";

            PopulateAdvancedNmapPorts(result.RawOutput);
        }
        catch (OperationCanceledException)
        {
            txtAdvNmapStatus.Text = "Cancelled";
        }
        catch (Exception ex)
        {
            txtAdvNmapStatus.Text = "Failed";
            txtAdvNmapRawOutput.AppendText(Environment.NewLine + $"[Error] {ex.Message}");
        }
        finally
        {
            progressAdvNmap.IsIndeterminate = false;
            btnAdvNmapStart.IsEnabled = true;
            btnAdvNmapStop.IsEnabled = false;
        }
    }

    private void BtnAdvNmapStop_Click(object sender, RoutedEventArgs e)
    {
        _nmapCancellation?.Cancel();
        txtAdvNmapStatus.Text = "Stopping...";
    }

    private void BtnAdvNmapCopy_Click(object sender, RoutedEventArgs e)
    {
        Clipboard.SetText(txtAdvNmapCommand.Text);
        txtAdvNmapStatus.Text = "Command copied";
    }

    private void PopulateAdvancedNmapPorts(string rawOutput)
    {
        _nmapPortItems.Clear();
        var lines = rawOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var match = System.Text.RegularExpressions.Regex.Match(line.Trim(), @"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?$");
            if (!match.Success)
            {
                continue;
            }

            var port = int.Parse(match.Groups[1].Value);
            var protocol = match.Groups[2].Value;
            var state = match.Groups[3].Value;
            var service = match.Groups[4].Value;
            var version = match.Groups[5].Value.Trim();

            if (!state.Equals("open", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var info = PortVulnerabilityDatabase.GetInfo(port);

            _nmapPortItems.Add(new NmapPortViewModel
            {
                Port = port,
                Protocol = protocol,
                Service = service,
                State = state,
                Version = version,
                RiskLevel = info.RiskLevel,
                Description = info.Description
            });
        }

        if (_nmapPortItems.Count == 0)
        {
            txtAdvNmapStatus.Text = "No open ports parsed";
        }
    }

    private void GridAdvNmapPorts_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (gridAdvNmapPorts.SelectedItem is not NmapPortViewModel selected)
        {
            ResetAdvancedNmapDetails();
            return;
        }

        var info = PortVulnerabilityDatabase.GetInfo(selected.Port);
        txtAdvNmapDetailHeader.Text = $"Port {selected.Port}/{selected.Protocol.ToUpperInvariant()}";
        txtAdvNmapDetailService.Text = info.ServiceName;
        txtAdvNmapDetailRisk.Text = $"Risk: {info.RiskLevel}";
        txtAdvNmapDetailRisk.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(PortVulnerabilityDatabase.GetRiskColor(info.RiskLevel)));
        txtAdvNmapDetailDescription.Text = string.IsNullOrWhiteSpace(info.Description) ? "No description" : info.Description;

        if (selected.Port == 445)
        {
            var result = NmapOutputParser.ParseMs17010Result(txtAdvNmapRawOutput.Text);
            var reason = NmapOutputParser.GetResultReason(result);
            txtAdvNmapMs17010.Text = $"MS17-010 Verdict: {result.ToString().ToUpperInvariant()}\n{reason}";
            txtAdvNmapMs17010.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(NmapOutputParser.GetResultColor(result)));

            var target = string.IsNullOrWhiteSpace(txtAdvNmapTarget.Text) ? "TARGET" : txtAdvNmapTarget.Text.Trim();
            txtAdvNmapNextCommands.Text =
                "Recommended next checks:\n" +
                $"1) nmap -p 445 --script smb-protocols {target}\n" +
                $"2) nmap -p 445 --script smb-vuln-ms17-010 --script-args smbuser=guest,smbpass= {target}\n" +
                $"3) nmap -p 445 --script smb2-security-mode,smb-security-mode {target}\n" +
                $"4) nmap -p 445 --script \"smb-vuln-*\" -v {target}";
        }
        else
        {
            txtAdvNmapMs17010.Text = "MS17-010 verdict is shown for port 445 selections.";
            txtAdvNmapMs17010.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#94A3B8"));
            txtAdvNmapNextCommands.Text = string.Empty;
        }

        scrollAdvNmapDetail.ScrollToTop();
    }

    private void ResetAdvancedNmapDetails()
    {
        txtAdvNmapDetailHeader.Text = "Select a port";
        txtAdvNmapDetailService.Text = string.Empty;
        txtAdvNmapDetailRisk.Text = string.Empty;
        txtAdvNmapDetailDescription.Text = string.Empty;
        txtAdvNmapMs17010.Text = "";
        txtAdvNmapNextCommands.Text = string.Empty;
    }

    private void LoadRecentScans()
    {
        using var db = new AppDbContext();
        var scans = db.Scans.OrderByDescending(s => s.ScanDate).Take(20).ToList();

        _scans.Clear();
        foreach (var scan in scans)
        {
            var vulnerabilities = string.IsNullOrWhiteSpace(scan.ResultsJson)
                ? new List<Vulnerability>()
                : JsonSerializer.Deserialize<List<Vulnerability>>(scan.ResultsJson) ?? new List<Vulnerability>();

            _scans.Add(new ScanViewModel
            {
                TargetUrl = scan.TargetUrl,
                ScanDate = scan.ScanDate,
                RiskScore = scan.RiskScore,
                PagesScanned = scan.PagesScanned,
                VulnerabilityCount = vulnerabilities.Count
            });
        }

        NotifyStatsChanged();
    }

    private async void BtnScan_Click(object sender, RoutedEventArgs e)
    {
        if (!Uri.TryCreate(txtTarget.Text, UriKind.Absolute, out _))
        {
            MessageBox.Show("Please enter a valid target URL.", "Invalid URL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        btnScan.IsEnabled = false;
        progressScan.Value = 0;
        progressScan.IsIndeterminate = true;
        ActiveScans = 1;
        NotifyStatsChanged();

        _currentScanner = new VulnerabilityScanner();
        _currentScanner.ProgressUpdate += (_, msg) => Dispatcher.Invoke(() => Title = msg);

        try
        {
            var result = await _currentScanner.ScanAsync(txtTarget.Text, chkDeepScan.IsChecked ?? false);
            _lastScanResult = result;
            gridVulns.ItemsSource = result.Vulnerabilities;

            SaveScanResult(result);
            LoadRecentScans();

            MessageBox.Show(
                $"Scan complete!\nFound {result.Vulnerabilities.Count} issues.\nRisk Score: {result.RiskScore}",
                "Scan Complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        finally
        {
            progressScan.IsIndeterminate = false;
            progressScan.Value = 100;
            btnScan.IsEnabled = true;
            ActiveScans = 0;
            NotifyStatsChanged();
            Title = "Web Vulnerability Scanner - Professional Edition";
        }
    }

    private static void SaveScanResult(ScanResult result)
    {
        using var db = new AppDbContext();
        db.Scans.Add(new ScanEntity
        {
            TargetUrl = result.TargetUrl,
            ScanDate = result.ScanDate,
            RiskScore = result.RiskScore,
            PagesScanned = result.PagesScanned,
            ResultsJson = JsonSerializer.Serialize(result.Vulnerabilities)
        });
        db.SaveChanges();
    }

    private void BtnProxyToggle_Click(object sender, RoutedEventArgs e)
    {
        if (_proxyServer?.IsRunning == true)
        {
            _proxyServer?.Stop();
            _proxyServer = null;

            btnProxyToggle.Content = "● Proxy OFF";
            btnProxyToggle.Background = new SolidColorBrush(Color.FromRgb(220, 38, 38));
            txtProxyStatus.Text = "Stopped";
            return;
        }

        if (!int.TryParse(txtProxyPort.Text, out var port))
        {
            MessageBox.Show("Invalid proxy port.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _proxyServer = new InterceptingProxyServer(port)
        {
            IsIntercepting = btnIntercept.IsChecked == true
        };

        _proxyServer.OnRequestCaptured += req => Dispatcher.Invoke(() =>
        {
            _proxyRequests.Insert(0, req);
            SaveProxyLog(req);
            NotifyStatsChanged();
            txtProxyStatus.Text = $"Captured: {req.Method} {req.Host}";
        });

        _proxyServer.OnResponseCaptured += req => Dispatcher.Invoke(() =>
        {
            if (_selectedRequest?.Id == req.Id)
            {
                txtResponseViewer.Text = string.IsNullOrWhiteSpace(req.ResponseBody)
                    ? "(no response body)"
                    : req.ResponseBody;
                txtStatusCode.Text = req.StatusCode > 0 ? $"HTTP {req.StatusCode}" : "";
            }
        });

        _proxyServer.OnLog += msg => Dispatcher.Invoke(() => Title = msg);
        _proxyServer.Start();

        btnProxyToggle.Content = "● Proxy ON";
        btnProxyToggle.Background = new SolidColorBrush(Color.FromRgb(22, 163, 74));
        txtProxyStatus.Text = $"Listening on 127.0.0.1:{port}";

        MessageBox.Show(
            $"Proxy started!\nConfigure your browser to use 127.0.0.1:{port}",
            "Proxy Active",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void GridProxy_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (gridProxy.SelectedItem is ProxyRequestEntry req)
        {
            _selectedRequest = req;
            txtRequestEditor.Text = req.RawRequest;
            txtResponseViewer.Text = string.IsNullOrWhiteSpace(req.ResponseBody)
                ? "(waiting for response...)"
                : req.ResponseBody;
            txtStatusCode.Text = req.StatusCode > 0 ? $"HTTP {req.StatusCode}" : "";
            txtProxyStatus.Text = $"Selected: {req.Method} {req.Host} at {req.Timestamp:HH:mm:ss}";
            return;
        }

        _selectedRequest = null;
        txtProxyStatus.Text = "No request selected";
    }

    private void BtnForward_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedRequest == null || _proxyServer == null)
        {
            return;
        }

        _proxyServer.Forward(_selectedRequest.Id, txtRequestEditor.Text);
        txtProxyStatus.Text = "Request forwarded";
    }

    private void BtnDrop_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedRequest == null || _proxyServer == null)
        {
            return;
        }

        _proxyServer.Drop(_selectedRequest.Id);
        txtProxyStatus.Text = "Request dropped";
    }

    private void BtnClearProxy_Click(object sender, RoutedEventArgs e)
    {
        _proxyRequests.Clear();
        _selectedRequest = null;
        txtRequestEditor.Text = string.Empty;
        txtResponseViewer.Text = string.Empty;
        txtStatusCode.Text = string.Empty;
        txtProxyStatus.Text = "Request list cleared";
        NotifyStatsChanged();
    }

    private void BtnCopyRequest_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(txtRequestEditor.Text))
        {
            Clipboard.SetText(txtRequestEditor.Text);
            txtProxyStatus.Text = "Request copied to clipboard";
        }
    }

    private void BtnIntercept_Checked(object sender, RoutedEventArgs e)
    {
        if (_proxyServer != null)
        {
            _proxyServer.IsIntercepting = true;
        }

        if (sender is System.Windows.Controls.Primitives.ToggleButton toggle)
        {
            toggle.Content = "⏸ Intercept ON";
        }

        if (txtProxyStatus != null)
        {
            txtProxyStatus.Text = "Intercept enabled";
        }
    }

    private void BtnIntercept_Unchecked(object sender, RoutedEventArgs e)
    {
        if (_proxyServer != null)
        {
            _proxyServer.IsIntercepting = false;
        }

        if (sender is System.Windows.Controls.Primitives.ToggleButton toggle)
        {
            toggle.Content = "▶ Intercept OFF";
        }

        if (txtProxyStatus != null)
        {
            txtProxyStatus.Text = "Intercept disabled";
        }
    }

    private void BtnReport_Click(object sender, RoutedEventArgs e)
    {
        if (_lastScanResult is null)
        {
            MessageBox.Show("Run a scan first to generate a report.", "Report", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var reportPath = PdfReportGenerator.Generate(_lastScanResult);
        MessageBox.Show($"Report generated:\n{reportPath}", "Report", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ScansGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
    }

    private async void BtnRepeaterSend_Click(object sender, RoutedEventArgs e)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            using var client = new HttpClient();

            var raw = txtRepeaterRequest.Text;
            if (string.IsNullOrWhiteSpace(raw))
            {
                txtRepeaterResponse.Text = "Request is empty.";
                return;
            }

            var lines = raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            var firstLine = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var method = firstLine.Length > 0 ? new HttpMethod(firstLine[0].Trim()) : HttpMethod.Get;

            using var request = new HttpRequestMessage(method, txtRepeaterUrl.Text);

            var lineIndex = 1;
            while (lineIndex < lines.Length && !string.IsNullOrWhiteSpace(lines[lineIndex]))
            {
                var parts = lines[lineIndex].Split(':', 2);
                if (parts.Length == 2)
                {
                    request.Headers.TryAddWithoutValidation(parts[0].Trim(), parts[1].Trim());
                }

                lineIndex++;
            }

            if (lineIndex + 1 < lines.Length)
            {
                var body = string.Join("\n", lines.Skip(lineIndex + 1));
                request.Content = new StringContent(body, Encoding.UTF8);
            }

            using var response = await client.SendAsync(request);
            sw.Stop();

            var responseBody = await response.Content.ReadAsStringAsync();
            var headers = string.Join("\n", response.Headers.Select(h => $"{h.Key}: {string.Join(",", h.Value)}"));

            txtRepeaterResponse.Text =
                $"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}\n{headers}\n\n{responseBody}";
            txtRepeaterStatus.Text = $"Status: {(int)response.StatusCode}";
            txtRepeaterTime.Text = $"Time: {sw.ElapsedMilliseconds}ms";
            txtRepeaterLength.Text = $"Length: {responseBody.Length}";
        }
        catch (Exception ex)
        {
            txtRepeaterResponse.Text = $"Error: {ex.Message}";
            txtRepeaterStatus.Text = "Status: Error";
            txtRepeaterTime.Text = "Time: —ms";
            txtRepeaterLength.Text = "Length: —";
        }
    }

    private void BtnRepeaterClear_Click(object sender, RoutedEventArgs e)
    {
        txtRepeaterRequest.Text = string.Empty;
        txtRepeaterResponse.Text = string.Empty;
        txtRepeaterStatus.Text = "Status: —";
        txtRepeaterTime.Text = "Time: —ms";
        txtRepeaterLength.Text = "Length: —";
    }

    private async void BtnAnalyzeHeaders_Click(object sender, RoutedEventArgs e)
    {
        if (!Uri.TryCreate(txtHeaderUrl.Text, UriKind.Absolute, out _))
        {
            MessageBox.Show("Enter a valid URL.", "Invalid URL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var analyzer = new SecurityHeaderAnalyzer();
            var findings = await analyzer.AnalyzeAsync(txtHeaderUrl.Text);
            gridHeaderFindings.ItemsSource = findings;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Header analysis failed: {ex.Message}", "Headers", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void BtnNmapScan_Click(object sender, RoutedEventArgs e)
    {
        btnNmapScan.IsEnabled = false;
        btnNmapStop.IsEnabled = true;
        progressNmap.Value = 0;
        txtNmapStatus.Text = "Starting...";
        txtHostsUp.Text = "0";
        txtOpenPorts.Text = "0";
        txtVulnCount.Text = "0";
        txtScanTime.Text = "0s";

        treeHosts.Items.Clear();
        gridPorts.ItemsSource = null;
        ResetVulnerabilityDetails();

        _networkScanStartedAt = DateTime.UtcNow;
        _netScanner = new NetworkScanner();

        _netScanner.OnStatusUpdate += message => Dispatcher.Invoke(() =>
        {
            txtNmapStatus.Text = message;
            txtScanTime.Text = $"{(DateTime.UtcNow - _networkScanStartedAt).TotalSeconds:F1}s";
        });

        _netScanner.OnProgressUpdate += percent => Dispatcher.Invoke(() =>
        {
            progressNmap.Value = percent;
            txtScanTime.Text = $"{(DateTime.UtcNow - _networkScanStartedAt).TotalSeconds:F1}s";
        });

        _netScanner.OnHostDiscovered += host => Dispatcher.Invoke(() => AddHostToTree(host));

        _netScanner.OnPortFound += port => Dispatcher.Invoke(() =>
        {
            if (int.TryParse(txtOpenPorts.Text, out var open))
            {
                txtOpenPorts.Text = (open + 1).ToString();
            }

            if (port.Risk != "OK" && int.TryParse(txtVulnCount.Text, out var vuln))
            {
                txtVulnCount.Text = (vuln + 1).ToString();
            }
        });

        var scanType = (cmbScanType.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "TCP Connect";
        var options = new NetworkScanOptions
        {
            Target = txtNmapTarget.Text,
            PortRange = txtNmapPorts.Text,
            ScanType = scanType,
            ServiceDetect = chkServiceDetect.IsChecked == true,
            OsDetect = chkOsDetect.IsChecked == true,
            VulnCheck = chkVulnCheck.IsChecked == true,
            SkipPing = scanType.Equals("Ping Only", StringComparison.OrdinalIgnoreCase)
        };

        try
        {
            await _netScanner.ScanAsync(options);
        }
        finally
        {
            btnNmapScan.IsEnabled = true;
            btnNmapStop.IsEnabled = false;
            txtScanTime.Text = $"{(DateTime.UtcNow - _networkScanStartedAt).TotalSeconds:F1}s";
        }
    }

    private void BtnNmapStop_Click(object sender, RoutedEventArgs e)
    {
        _netScanner?.Stop();
        btnNmapScan.IsEnabled = true;
        btnNmapStop.IsEnabled = false;
    }

    private void AddHostToTree(ScanHost host)
    {
        var color = host.RiskLevel == "VULNERABLE" ? "#F87171" : "#4ADE80";

        var item = new TreeViewItem
        {
            Header = $"[{host.IpAddress}] {host.Hostname}",
            Tag = host,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color))
        };

        item.Items.Add(new TreeViewItem { Header = $"OS: {host.OsGuess}" });
        item.Items.Add(new TreeViewItem { Header = $"Open ports: {host.OpenCount}" });

        treeHosts.Items.Add(item);
        txtHostsUp.Text = treeHosts.Items.Count.ToString();
    }

    private void TreeHosts_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is TreeViewItem { Tag: ScanHost host })
        {
            _selectedHost = host;
            gridPorts.ItemsSource = host.Ports;
            ResetVulnerabilityDetails();
        }
    }

    private void GridPorts_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (gridPorts.SelectedItem is not PortResult selectedPort)
        {
            ResetVulnerabilityDetails();
            return;
        }

        var info = PortVulnerabilityDatabase.GetInfo(selectedPort.Port);

        // Service info
        txtVulnName.Text = $"🔌 Port {selectedPort.Port}/{info.Protocol} — {info.ServiceName}";
        txtVulnRisk.Text = $"Risk Level: {info.RiskLevel}";

        var riskHex = PortVulnerabilityDatabase.GetRiskColor(info.RiskLevel);
        var riskColor = (Color)ColorConverter.ConvertFromString(riskHex);
        txtVulnRisk.Foreground = new SolidColorBrush(riskColor);

        // Attack type
        txtVulnDescription.Text = $"⚔️ Attack Type: {info.AttackType}\n\n📝 {info.Description}";

        // CVEs
        if (info.CVEs.Length > 0)
        {
            txtVulnCVEs.Text = $"🐛 CVEs:\n• {string.Join("\n• ", info.CVEs)}";
        }
        else
        {
            txtVulnCVEs.Text = "🐛 CVEs: —";
        }

        // Impact
        txtVulnImpact.Text = string.IsNullOrWhiteSpace(info.Impact)
            ? "💥 Impact: —"
            : $"💥 Impact:\n{info.Impact}";

        // Fix steps
        if (info.HowToFix.Length > 0)
        {
            var fixText = "✅ How to Fix:\n" + string.Join("\n", info.HowToFix.Select((fix, i) => $"{i + 1}. {fix}"));
            txtVulnFix.Text = fixText;
        }
        else
        {
            txtVulnFix.Text = "✅ Fix: —";
        }

        // Tools
        txtVulnTools.Text = string.IsNullOrWhiteSpace(info.ToolsToTest)
            ? "🔧 Tools: —"
            : $"🔧 Tools:\n{info.ToolsToTest}";
    }

    private void ResetVulnerabilityDetails()
    {
        txtVulnName.Text = "Select a port to view vulnerability details";
        txtVulnRisk.Text = "Risk: —";
        txtVulnRisk.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E2E8F0"));
        txtVulnDescription.Text = "Description: —";
        txtVulnCVEs.Text = "CVEs: —";
        txtVulnImpact.Text = "Impact: —";
        txtVulnFix.Text = "Fix: —";
        txtVulnTools.Text = "Tools: —";
    }

    private void BtnNmapExport_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var hosts = treeHosts.Items
                .Cast<TreeViewItem>()
                .Select(item => item.Tag as ScanHost)
                .Where(host => host != null)
                .Cast<ScanHost>()
                .ToList();

            if (hosts.Count == 0)
            {
                txtNmapStatus.Text = "Nothing to export.";
                return;
            }

            var exportData = hosts.Select(host => new
            {
                IpAddress = host.IpAddress.ToString(),
                host.Hostname,
                host.OsGuess,
                host.MacAddress,
                host.OpenCount,
                host.RiskLevel,
                Ports = host.Ports.Select(port => new
                {
                    port.Port,
                    port.Protocol,
                    port.State,
                    port.Service,
                    port.Version,
                    port.Risk,
                    port.Details
                }).ToList()
            }).ToList();

            var json = JsonSerializer.Serialize(exportData, new JsonSerializerOptions { WriteIndented = true });
            var fileName = $"netscan_{DateTime.Now:yyyyMMdd_HHmm}.json";

            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var path = Path.Combine(desktop, fileName);

            try
            {
                File.WriteAllText(path, json);
            }
            catch
            {
                var fallbackDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "WebVulnScanner",
                    "exports");
                Directory.CreateDirectory(fallbackDir);
                path = Path.Combine(fallbackDir, fileName);
                File.WriteAllText(path, json);
            }

            txtNmapStatus.Text = $"Exported to {path}";
        }
        catch (Exception ex)
        {
            txtNmapStatus.Text = $"Export failed: {ex.Message}";
        }
    }

    private void Encode_Base64(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(txtEncodeInput.Text));
    }

    private void Decode_Base64(object sender, RoutedEventArgs e)
    {
        TrySetEncodeOutput(() => Encoding.UTF8.GetString(Convert.FromBase64String(txtEncodeInput.Text)));
    }

    private void Encode_Url(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = Uri.EscapeDataString(txtEncodeInput.Text);
    }

    private void Decode_Url(object sender, RoutedEventArgs e)
    {
        TrySetEncodeOutput(() => Uri.UnescapeDataString(txtEncodeInput.Text));
    }

    private void Encode_Html(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = WebUtility.HtmlEncode(txtEncodeInput.Text);
    }

    private void Decode_Html(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = WebUtility.HtmlDecode(txtEncodeInput.Text);
    }

    private void Hash_MD5(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(txtEncodeInput.Text)));
    }

    private void Hash_SHA256(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(txtEncodeInput.Text)));
    }

    private void Decode_JWT(object sender, RoutedEventArgs e)
    {
        TrySetEncodeOutput(() =>
        {
            var parts = txtEncodeInput.Text.Split('.');
            if (parts.Length != 3)
            {
                return "Invalid JWT";
            }

            string Pad(string value)
            {
                var normalized = value.Replace('-', '+').Replace('_', '/');
                var pad = (4 - normalized.Length % 4) % 4;
                return normalized.PadRight(normalized.Length + pad, '=');
            }

            var header = Encoding.UTF8.GetString(Convert.FromBase64String(Pad(parts[0])));
            var payload = Encoding.UTF8.GetString(Convert.FromBase64String(Pad(parts[1])));

            return $"=== HEADER ===\n{JsonPrettyPrint(header)}\n\n=== PAYLOAD ===\n{JsonPrettyPrint(payload)}\n\n=== SIGNATURE ===\n{parts[2]}";
        });
    }

    private void Encode_Hex(object sender, RoutedEventArgs e)
    {
        txtEncodeOutput.Text = Convert.ToHexString(Encoding.UTF8.GetBytes(txtEncodeInput.Text));
    }

    private void Decode_Hex(object sender, RoutedEventArgs e)
    {
        TrySetEncodeOutput(() => Encoding.UTF8.GetString(Convert.FromHexString(txtEncodeInput.Text.Replace(" ", "", StringComparison.Ordinal))));
    }

    private void TrySetEncodeOutput(Func<string> action)
    {
        try
        {
            txtEncodeOutput.Text = action();
        }
        catch (Exception ex)
        {
            txtEncodeOutput.Text = $"Error: {ex.Message}";
        }
    }

    private static string JsonPrettyPrint(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
    }

    private static void SaveProxyLog(ProxyRequestEntry req)
    {
        try
        {
            using var db = new AppDbContext();
            db.ProxyLogs.Add(new ProxyLogEntity
            {
                Method = req.Method,
                Url = req.Url,
                RawRequest = req.RawRequest,
                Timestamp = req.Timestamp,
                WasModified = !string.IsNullOrWhiteSpace(req.RawRequest)
            });
            db.SaveChanges();
        }
        catch
        {
        }
    }

    private void NotifyStatsChanged()
    {
        OnPropertyChanged(nameof(TotalScans));
        OnPropertyChanged(nameof(CriticalCount));
        OnPropertyChanged(nameof(ProxyRequestCount));
        OnPropertyChanged(nameof(ActiveScans));
        OnPropertyChanged(nameof(RecentScans));
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        _proxyServer?.Dispose();
    }
}

public class ScanViewModel
{
    public string TargetUrl { get; set; } = "";
    public DateTime ScanDate { get; set; }
    public int RiskScore { get; set; }
    public int PagesScanned { get; set; }
    public int VulnerabilityCount { get; set; }
}

public class NmapPortViewModel
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "tcp";
    public string Service { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string RiskLevel { get; set; } = "Info";
    public string Description { get; set; } = string.Empty;
}