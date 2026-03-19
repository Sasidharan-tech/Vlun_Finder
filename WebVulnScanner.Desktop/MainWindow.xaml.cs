using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WebVulnScanner.Core.Database;
using WebVulnScanner.Core.Models;
using WebVulnScanner.Core.Proxy;
using WebVulnScanner.Core.Reports;
using WebVulnScanner.Core.Scanner;

namespace WebVulnScanner.Desktop;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private InterceptingProxy? _proxy;
    private readonly ObservableCollection<InterceptedRequest> _proxyRequests = new();
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
        LoadRecentScans();
        NotifyStatsChanged();
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
        if (_proxy?.IsRunning == true)
        {
            _proxy.Stop();
            _proxy.Dispose();
            _proxy = null;

            btnProxyToggle.Content = "Proxy: OFF";
            btnProxyToggle.Background = new SolidColorBrush(Color.FromRgb(231, 76, 60));
            txtProxyStatus.Text = "Proxy stopped";
            return;
        }

        if (!int.TryParse(txtProxyPort.Text, out var port))
        {
            MessageBox.Show("Invalid proxy port.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _proxy = new InterceptingProxy { Port = port };
        _proxy.RequestCaptured += (_, req) => Dispatcher.Invoke(() =>
        {
            _proxyRequests.Insert(0, req);
            SaveProxyLog(req);
            NotifyStatsChanged();
            txtProxyStatus.Text = $"Captured: {req.Method} {req.Host}";
        });
        _proxy.LogMessage += (_, msg) => Dispatcher.Invoke(() => Title = msg);
        _proxy.Start();

        btnProxyToggle.Content = "Proxy: ON";
        btnProxyToggle.Background = new SolidColorBrush(Color.FromRgb(39, 174, 96));
        txtProxyStatus.Text = $"Proxy running on 127.0.0.1:{port}";

        MessageBox.Show(
            $"Proxy started!\nConfigure your browser to use 127.0.0.1:{port}",
            "Proxy Active",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void GridProxy_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (gridProxy.SelectedItem is InterceptedRequest req)
        {
            txtRequestEditor.Text = req.RawRequest;
            txtProxyStatus.Text = $"Selected: {req.Method} {req.Host} at {req.Timestamp:HH:mm:ss}";
            return;
        }

        txtProxyStatus.Text = "No request selected";
    }

    private void BtnForward_Click(object sender, RoutedEventArgs e)
    {
        if (gridProxy.SelectedItem is InterceptedRequest req)
        {
            ApplyEditorChangesToRequest(req);
        }

        _proxy?.ForwardCurrentRequest();
    }

    private void BtnDrop_Click(object sender, RoutedEventArgs e)
    {
        _proxy?.DropCurrentRequest();
    }

    private void BtnClearProxy_Click(object sender, RoutedEventArgs e)
    {
        _proxyRequests.Clear();
        txtRequestEditor.Text = string.Empty;
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
        _proxy?.SetInterceptMode(true);

        if (sender is System.Windows.Controls.Primitives.ToggleButton toggle)
        {
            toggle.Content = "Intercept: ON";
        }

        if (txtProxyStatus != null)
        {
            txtProxyStatus.Text = "Intercept enabled";
        }
    }

    private void BtnIntercept_Unchecked(object sender, RoutedEventArgs e)
    {
        _proxy?.SetInterceptMode(false);

        if (sender is System.Windows.Controls.Primitives.ToggleButton toggle)
        {
            toggle.Content = "Intercept: OFF";
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

    private static void SaveProxyLog(InterceptedRequest req)
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
                WasModified = req.Modified
            });
            db.SaveChanges();
        }
        catch
        {
        }
    }

    private void ApplyEditorChangesToRequest(InterceptedRequest req)
    {
        var edited = txtRequestEditor.Text;
        if (string.IsNullOrWhiteSpace(edited) || string.Equals(edited, req.RawRequest, StringComparison.Ordinal))
        {
            return;
        }

        req.RawRequest = edited;
        req.Modified = true;

        var splitIndex = edited.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var separatorLength = 4;
        if (splitIndex < 0)
        {
            splitIndex = edited.IndexOf("\n\n", StringComparison.Ordinal);
            separatorLength = splitIndex >= 0 ? 2 : 0;
        }

        var headerPart = splitIndex >= 0 ? edited[..splitIndex] : edited;
        var bodyPart = splitIndex >= 0 ? edited[(splitIndex + separatorLength)..] : "";

        var lines = headerPart.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n', StringSplitOptions.None);
        if (lines.Length == 0)
        {
            return;
        }

        var firstParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (firstParts.Length >= 2)
        {
            req.Method = firstParts[0];

            var hostHeader = req.Headers.GetValueOrDefault("Host", req.Host);
            if (!string.IsNullOrWhiteSpace(hostHeader) && firstParts[1].StartsWith('/'))
            {
                var scheme = req.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? "https://" : "http://";
                req.Url = scheme + hostHeader + firstParts[1];
            }
            else
            {
                req.Url = firstParts[1];
            }
        }

        var newHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon > 0)
            {
                var key = line[..colon].Trim();
                var value = line[(colon + 1)..].Trim();
                newHeaders[key] = value;
            }
        }

        if (newHeaders.Count > 0)
        {
            req.Headers = newHeaders;
            req.Host = newHeaders.GetValueOrDefault("Host", req.Host);
        }

        req.Body = bodyPart;
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
        _proxy?.Dispose();
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