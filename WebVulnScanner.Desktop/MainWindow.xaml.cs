using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WebVulnScanner.Core.Database;
using WebVulnScanner.Core.Models;
using WebVulnScanner.Core.OpenVAS;
using WebVulnScanner.Core.Proxy;
using WebVulnScanner.Core.RiskDetector;
using WebVulnScanner.Core.Reports;
using WebVulnScanner.Core.NmapIntegration;
using WebVulnScanner.Core.Scanner;

namespace WebVulnScanner.Desktop;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private const double BaseUiFontSize = 13.0;
    private static readonly DependencyProperty BaseFontSizeProperty = DependencyProperty.RegisterAttached(
        "BaseFontSize",
        typeof(double),
        typeof(MainWindow),
        new PropertyMetadata(double.NaN));

    private static readonly DependencyProperty BaseFontFamilyProperty = DependencyProperty.RegisterAttached(
        "BaseFontFamily",
        typeof(FontFamily),
        typeof(MainWindow),
        new PropertyMetadata(null));

    private readonly string _settingsFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "WebVulnScanner",
        "ui-settings.json");

    private InterceptingProxyServer? _proxyServer;
    private ProxyRequestEntry? _selectedRequest;
    private NetworkScanner? _netScanner;
    private ScanHost? _selectedHost;
    private DateTime _networkScanStartedAt;
    private NmapRunner? _nmapRunner;
    private CancellationTokenSource? _nmapCancellation;
    private readonly ObservableCollection<NmapPortViewModel> _nmapPortItems = new();
    private OpenVasScanEngine? _ovasEngine;
    private readonly ObservableCollection<OpenVasResult> _ovasResults = new();

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
        InitOpenVasTab();
        SyncSettingsFormFromCurrentUi();
        LoadApplicationSettings();
        LoadRecentScans();
        NotifyStatsChanged();
    }

    private void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var settings = ReadSettingsFromForm();
            var directory = Path.GetDirectoryName(_settingsFilePath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_settingsFilePath, json);

            ApplySettingsToUi(settings);
            txtSettingsStatus.Text = $"Saved: {_settingsFilePath}";
        }
        catch (Exception ex)
        {
            txtSettingsStatus.Text = $"Save failed: {ex.Message}";
        }
    }

    private void BtnLoadSettings_Click(object sender, RoutedEventArgs e)
    {
        LoadApplicationSettings();
    }

    private void BtnResetSettings_Click(object sender, RoutedEventArgs e)
    {
        var defaults = new ApplicationUiSettings();
        ApplySettingsToUi(defaults);
        SyncSettingsFormFromCurrentUi();
        txtSettingsStatus.Text = "Reset to defaults (not saved yet)";
    }

    private void LoadApplicationSettings()
    {
        try
        {
            if (!File.Exists(_settingsFilePath))
            {
                txtSettingsStatus.Text = "No saved settings file found";
                return;
            }

            var json = File.ReadAllText(_settingsFilePath);
            var settings = JsonSerializer.Deserialize<ApplicationUiSettings>(json) ?? new ApplicationUiSettings();

            ApplySettingsToUi(settings);
            SyncSettingsFormFromCurrentUi();
            txtSettingsStatus.Text = "Loaded saved settings";
        }
        catch (Exception ex)
        {
            txtSettingsStatus.Text = $"Load failed: {ex.Message}";
        }
    }

    private void SyncSettingsFormFromCurrentUi()
    {
        txtSetDefaultTargetUrl.Text = txtTarget.Text;
        chkSetDefaultDeepScan.IsChecked = chkDeepScan.IsChecked == true;
        txtSetProxyPort.Text = txtProxyPort.Text;
        txtSetNmapTarget.Text = txtNmapTarget.Text;
        txtSetNmapPorts.Text = txtNmapPorts.Text;
        txtSetOvasHost.Text = txtOvasHost.Text;
        txtSetOvasPort.Text = txtOvasPort.Text;
        txtSetOvasUser.Text = txtOvasUser.Text;

        if (cmbSetThemeMode.SelectedIndex < 0)
        {
            cmbSetThemeMode.SelectedIndex = 0;
        }

        if (cmbSetFontSize.SelectedIndex < 0)
        {
            cmbSetFontSize.SelectedIndex = 2;
        }

        if (cmbSetFontStyle.SelectedIndex < 0)
        {
            cmbSetFontStyle.SelectedIndex = 0;
        }
    }

    private ApplicationUiSettings ReadSettingsFromForm()
    {
        var settings = new ApplicationUiSettings
        {
            DefaultTargetUrl = txtSetDefaultTargetUrl.Text.Trim(),
            DeepScanByDefault = chkSetDefaultDeepScan.IsChecked == true,
            DefaultProxyPort = int.TryParse(txtSetProxyPort.Text, out var proxyPort) ? proxyPort : 8080,
            DefaultNmapTarget = txtSetNmapTarget.Text.Trim(),
            DefaultNmapPorts = string.IsNullOrWhiteSpace(txtSetNmapPorts.Text) ? "1-1024" : txtSetNmapPorts.Text.Trim(),
            DefaultOvasHost = txtSetOvasHost.Text.Trim(),
            DefaultOvasPort = int.TryParse(txtSetOvasPort.Text, out var ovasPort) ? ovasPort : 9390,
            DefaultOvasUser = string.IsNullOrWhiteSpace(txtSetOvasUser.Text) ? "admin" : txtSetOvasUser.Text.Trim(),
            ThemeMode = GetComboText(cmbSetThemeMode, "System default"),
            TextFontSize = double.TryParse(GetComboText(cmbSetFontSize, "13"), out var fontSize) ? fontSize : 13,
            TextStyle = GetComboText(cmbSetFontStyle, "Default")
        };

        return settings;
    }

    private void ApplySettingsToUi(ApplicationUiSettings settings)
    {
        txtTarget.Text = settings.DefaultTargetUrl;
        chkDeepScan.IsChecked = settings.DeepScanByDefault;
        txtProxyPort.Text = settings.DefaultProxyPort.ToString();
        txtNmapTarget.Text = settings.DefaultNmapTarget;
        txtNmapPorts.Text = settings.DefaultNmapPorts;
        txtOvasHost.Text = settings.DefaultOvasHost;
        txtOvasPort.Text = settings.DefaultOvasPort.ToString();
        txtOvasUser.Text = settings.DefaultOvasUser;

        SetComboByText(cmbSetThemeMode, settings.ThemeMode, "System default");
        SetComboByText(cmbSetFontSize, settings.TextFontSize.ToString("0"), "13");
        SetComboByText(cmbSetFontStyle, settings.TextStyle, "Default");

        ApplyAppearance(settings.ThemeMode, settings.TextFontSize, settings.TextStyle);

        UpdateAdvNmapCommandPreview();
    }

    private void BtnApplyAppearance_Click(object sender, RoutedEventArgs e)
    {
        var settings = ReadSettingsFromForm();
        ApplyAppearance(settings.ThemeMode, settings.TextFontSize, settings.TextStyle);
        txtSettingsStatus.Text = "Appearance applied";
    }

    private void ApplyAppearance(string themeMode, double fontSize, string textStyle)
    {
        var mode = string.IsNullOrWhiteSpace(themeMode) ? "System default" : themeMode;
        var resolvedDark = mode.Equals("Dark", StringComparison.OrdinalIgnoreCase)
            || (mode.Equals("System default", StringComparison.OrdinalIgnoreCase) && IsSystemDarkTheme());

        if (resolvedDark)
        {
            UpdateBrushColor("BrushBackground", "#0F172A");
            UpdateBrushColor("BrushSurface", "#111827");
            UpdateBrushColor("BrushSurfaceAlt", "#1F2937");
            UpdateBrushColor("BrushBorder", "#334155");
            UpdateBrushColor("BrushTextPrimary", "#F8FAFC");
            UpdateBrushColor("BrushTextSecondary", "#E2E8F0");
            UpdateBrushColor("BrushChromeBackground", "#0B1220");
            UpdateBrushColor("BrushTabBackground", "#1F2937");
            UpdateBrushColor("BrushTabSelectedBackground", "#0F172A");
            UpdateBrushColor("BrushTabHoverBackground", "#334155");
            UpdateBrushColor("BrushDataGridRow", "#0F1A2E");
            UpdateBrushColor("BrushDataGridRowAlt", "#111F36");
            UpdateBrushColor("BrushDataGridRowHover", "#1E3A5F");
            UpdateBrushColor("BrushDataGridRowSelected", "#0EA5E9");
            UpdateBrushColor("BrushDataGridGridlineH", "#243244");
            UpdateBrushColor("BrushDataGridGridlineV", "#1B2533");
        }
        else
        {
            UpdateBrushColor("BrushBackground", "#F8FAFC");
            UpdateBrushColor("BrushSurface", "#FFFFFF");
            UpdateBrushColor("BrushSurfaceAlt", "#F1F5F9");
            UpdateBrushColor("BrushBorder", "#CBD5E1");
            UpdateBrushColor("BrushTextPrimary", "#0F172A");
            UpdateBrushColor("BrushTextSecondary", "#334155");
            UpdateBrushColor("BrushChromeBackground", "#E2E8F0");
            UpdateBrushColor("BrushTabBackground", "#E2E8F0");
            UpdateBrushColor("BrushTabSelectedBackground", "#FFFFFF");
            UpdateBrushColor("BrushTabHoverBackground", "#CBD5E1");
            UpdateBrushColor("BrushDataGridRow", "#FFFFFF");
            UpdateBrushColor("BrushDataGridRowAlt", "#F8FAFC");
            UpdateBrushColor("BrushDataGridRowHover", "#E2E8F0");
            UpdateBrushColor("BrushDataGridRowSelected", "#93C5FD");
            UpdateBrushColor("BrushDataGridGridlineH", "#CBD5E1");
            UpdateBrushColor("BrushDataGridGridlineV", "#E2E8F0");
        }

        ApplyTypography(fontSize, textStyle);
    }

    private void ApplyTypography(double fontSize, string textStyle)
    {
        var clamped = Math.Clamp(fontSize, 10, 24);
        var scale = clamped / BaseUiFontSize;
        var useDefaultFamily = string.Equals(textStyle, "Default", StringComparison.OrdinalIgnoreCase);
        var targetFamily = new FontFamily(MapFontStyleToFamily(textStyle));

        ApplyTypographyRecursive(this, scale, targetFamily, useDefaultFamily);
    }

    private static void ApplyTypographyRecursive(DependencyObject node, double scale, FontFamily targetFamily, bool useDefaultFamily)
    {
        switch (node)
        {
            case Control control:
                ApplyFontForElement(control, scale, targetFamily, useDefaultFamily, Control.FontSizeProperty, Control.FontFamilyProperty);
                break;
            case TextBlock textBlock:
                ApplyFontForElement(textBlock, scale, targetFamily, useDefaultFamily, TextBlock.FontSizeProperty, TextBlock.FontFamilyProperty);
                break;
        }

        var childCount = VisualTreeHelper.GetChildrenCount(node);
        for (var i = 0; i < childCount; i++)
        {
            ApplyTypographyRecursive(VisualTreeHelper.GetChild(node, i), scale, targetFamily, useDefaultFamily);
        }
    }

    private static void ApplyFontForElement(
        DependencyObject element,
        double scale,
        FontFamily targetFamily,
        bool useDefaultFamily,
        DependencyProperty fontSizeProperty,
        DependencyProperty fontFamilyProperty)
    {
        if (element.ReadLocalValue(BaseFontSizeProperty) == DependencyProperty.UnsetValue)
        {
            element.SetValue(BaseFontSizeProperty, (double)element.GetValue(fontSizeProperty));
        }

        if (element.ReadLocalValue(BaseFontFamilyProperty) == DependencyProperty.UnsetValue)
        {
            element.SetValue(BaseFontFamilyProperty, (FontFamily)element.GetValue(fontFamilyProperty));
        }

        var baseSize = (double)element.GetValue(BaseFontSizeProperty);
        var baseFamily = (FontFamily)element.GetValue(BaseFontFamilyProperty);

        var scaled = Math.Clamp(baseSize * scale, 8, 60);
        element.SetCurrentValue(fontSizeProperty, scaled);
        element.SetCurrentValue(fontFamilyProperty, useDefaultFamily ? baseFamily : targetFamily);
    }

    private static string GetComboText(ComboBox comboBox, string fallback)
    {
        if (comboBox.SelectedItem is ComboBoxItem selected && selected.Content is string selectedText)
        {
            return selectedText;
        }

        return fallback;
    }

    private static void SetComboByText(ComboBox comboBox, string text, string fallback)
    {
        var valueToFind = string.IsNullOrWhiteSpace(text) ? fallback : text;

        foreach (var item in comboBox.Items)
        {
            if (item is ComboBoxItem comboItem && string.Equals(comboItem.Content?.ToString(), valueToFind, StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedItem = comboItem;
                return;
            }
        }

        foreach (var item in comboBox.Items)
        {
            if (item is ComboBoxItem comboItem && string.Equals(comboItem.Content?.ToString(), fallback, StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedItem = comboItem;
                return;
            }
        }
    }

    private void UpdateBrushColor(string key, string hex)
    {
        if (Resources[key] is SolidColorBrush brush)
        {
            brush.Color = (Color)ColorConverter.ConvertFromString(hex);
        }
    }

    private static bool IsSystemDarkTheme()
    {
        try
        {
            const string personalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
            using var key = Registry.CurrentUser.OpenSubKey(personalizeKey);
            var value = key?.GetValue("AppsUseLightTheme");

            if (value is int intValue)
            {
                return intValue == 0;
            }
        }
        catch
        {
        }

        return true;
    }

    private static string MapFontStyleToFamily(string textStyle)
    {
        return textStyle.ToLowerInvariant() switch
        {
            "classic" => "Georgia",
            "modern" => "Bahnschrift",
            "monospace" => "Consolas",
            _ => "Segoe UI"
        };
    }

    private void InitOpenVasTab()
    {
        gridOvasResults.ItemsSource = _ovasResults;
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
        if (txtAdvNmapTarget is null || cmbAdvNmapProfile is null || txtAdvNmapCommand is null)
        {
            return;
        }

        UpdateAdvNmapCommandPreview();
    }

    private void UpdateAdvNmapCommandPreview()
    {
        if (txtAdvNmapTarget is null || cmbAdvNmapProfile is null || txtAdvNmapCommand is null)
        {
            return;
        }

        var target = string.IsNullOrWhiteSpace(txtAdvNmapTarget.Text) ? "<target>" : txtAdvNmapTarget.Text.Trim();
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
        if (string.IsNullOrWhiteSpace(txtAdvNmapTarget.Text))
        {
            MessageBox.Show("Enter a target host before starting the scan.", "Nmap", MessageBoxButton.OK, MessageBoxImage.Information);
            txtAdvNmapTarget.Focus();
            return;
        }

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
        riskResultBorder.Visibility = Visibility.Collapsed;

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
                    UpdateAdvancedNmapStageStatus(line);
                });
            });

            var result = await _nmapRunner.RunAsync(args, progress, _nmapCancellation.Token);
            txtAdvNmapStatus.Text = result.Success ? "Completed" : "Completed with errors";

            PopulateAdvancedNmapPorts(result.RawOutput);
            ShowRiskResult(result.RawOutput);
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

    private void UpdateAdvancedNmapStageStatus(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        if (line.Contains("ARP Ping", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Ping Scan", StringComparison.OrdinalIgnoreCase)
            || line.Contains("host discovery", StringComparison.OrdinalIgnoreCase))
        {
            txtAdvNmapStatus.Text = "Host discovery...";
        }
        else if (line.Contains("SYN Stealth", StringComparison.OrdinalIgnoreCase)
                 || line.Contains("Port Scan", StringComparison.OrdinalIgnoreCase)
                 || line.Contains("scanning", StringComparison.OrdinalIgnoreCase))
        {
            txtAdvNmapStatus.Text = "Port scanning...";
        }
        else if (line.Contains("NSE: Script scanning", StringComparison.OrdinalIgnoreCase)
                 || line.Contains("--script", StringComparison.OrdinalIgnoreCase))
        {
            txtAdvNmapStatus.Text = "Running vuln scripts...";
        }
        else if (line.Contains("Host seems down", StringComparison.OrdinalIgnoreCase)
                 || line.Contains("0 hosts up", StringComparison.OrdinalIgnoreCase))
        {
            txtAdvNmapStatus.Text = "Host down";
        }
        else if (line.Contains("Nmap done", StringComparison.OrdinalIgnoreCase))
        {
            txtAdvNmapStatus.Text = "Complete";
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

    private void ShowRiskResult(string nmapRawOutput)
    {
        var report = RiskDetector.Analyze(nmapRawOutput);

        riskResultBorder.Visibility = Visibility.Visible;

        var backgroundColor = (Color)ColorConverter.ConvertFromString(report.VerdictBg);
        var borderColor = (Color)ColorConverter.ConvertFromString(report.VerdictColor);

        verdictBadge.Background = new SolidColorBrush(backgroundColor);
        verdictBadge.BorderBrush = new SolidColorBrush(borderColor);

        riskResultBorder.Background = new SolidColorBrush(backgroundColor) { Opacity = 0.45 };
        riskResultBorder.BorderBrush = new SolidColorBrush(borderColor) { Opacity = 0.8 };

        txtVerdictIcon.Text = report.VerdictIcon;
        txtVerdictMain.Text = report.Verdict;
        txtVerdictTarget.Text = string.IsNullOrWhiteSpace(report.IpAddress)
            ? txtAdvNmapTarget.Text
            : report.IpAddress;
        txtVerdictDetail.Text = report.VerdictDetail;

        listRiskFindings.ItemsSource = report.Findings;
        listSafePoints.ItemsSource = report.SafePoints;
        listNextSteps.ItemsSource = report.NextSteps;

        if (report.CriticalCount + report.HighCount > 0)
        {
            txtVulnCount.Text = (report.CriticalCount + report.HighCount).ToString();
            txtVulnCount.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(report.VerdictColor));
        }
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

    private void BtnForwardAll_Click(object sender, RoutedEventArgs e)
    {
        if (_proxyServer == null)
        {
            txtProxyStatus.Text = "Proxy is not running";
            return;
        }

        var forwardedCount = _proxyServer.ForwardAll();
        txtProxyStatus.Text = forwardedCount > 0
            ? $"Forwarded {forwardedCount} pending request(s)"
            : "No pending intercepted requests";
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
        progressNmap.IsIndeterminate = true;
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
            if (progressNmap.IsIndeterminate)
            {
                progressNmap.IsIndeterminate = false;
            }
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
            progressNmap.IsIndeterminate = false;
            txtScanTime.Text = $"{(DateTime.UtcNow - _networkScanStartedAt).TotalSeconds:F1}s";
        }
    }

    private void BtnNmapStop_Click(object sender, RoutedEventArgs e)
    {
        _netScanner?.Stop();
        txtNmapStatus.Text = "Stopping...";
        progressNmap.IsIndeterminate = true;
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

    private async void BtnOvasTestConn_Click(object sender, RoutedEventArgs e)
    {
        ovasConnStatus.Text = "Testing...";
        ovasConnBadge.Background = new SolidColorBrush(Color.FromRgb(30, 41, 59));
        ovasConnBadge.BorderBrush = null;
        ovasConnBadge.BorderThickness = new Thickness(0);

        var settings = GetOvasSettings();
        using var client = new OpenVasClient(settings);

        try
        {
            await client.ConnectAsync();
            ovasConnStatus.Text = "Connected";
            ovasConnBadge.Background = new SolidColorBrush(Color.FromRgb(15, 68, 24));
            ovasConnBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(22, 163, 74));
            ovasConnBadge.BorderThickness = new Thickness(1);
            ovasConnStatus.Foreground = new SolidColorBrush(Color.FromRgb(74, 222, 128));
        }
        catch (Exception ex)
        {
            ovasConnStatus.Text = $"Failed: {ex.Message}";
            ovasConnBadge.Background = new SolidColorBrush(Color.FromRgb(68, 15, 15));
            ovasConnBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 38, 38));
            ovasConnBadge.BorderThickness = new Thickness(1);
            ovasConnStatus.Foreground = new SolidColorBrush(Color.FromRgb(248, 113, 113));
        }
    }

    private async void BtnOvasScan_Click(object sender, RoutedEventArgs e)
    {
        _ovasResults.Clear();
        ovasCritCount.Text = ovasHighCount.Text = ovasMedCount.Text = ovasLowCount.Text = ovasTotalCount.Text = "0";
        ovasEmptyPanel.Visibility = Visibility.Visible;
        ovasDetailPanel.Visibility = Visibility.Collapsed;

        btnOvasScan.IsEnabled = false;
        btnOvasStop.IsEnabled = true;
        progressOvas.Value = 0;
        progressOvas.IsIndeterminate = false;

        var profileName = (cmbOvasProfile.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Full and fast";
        profileName = profileName.Split('(')[0].Trim();

        var options = new ScanEngineOptions
        {
            Connection = GetOvasSettings(),
            Target = txtOvasTarget.Text.Trim(),
            TaskName = txtOvasTaskName.Text.Trim(),
            ScanProfile = profileName
        };

        _ovasEngine = new OpenVasScanEngine();

        _ovasEngine.OnLog += msg =>
            Dispatcher.Invoke(() => txtOvasStatus.Text = msg);

        _ovasEngine.OnProgress += progress =>
            Dispatcher.Invoke(() =>
            {
                txtOvasStatus.Text = progress.Message;
                txtOvasPercent.Text = progress.Percent > 0 ? $"{progress.Percent}%" : string.Empty;
                progressOvas.Value = progress.Percent;
                progressOvas.IsIndeterminate = progress.Status == "Connecting";
            });

        _ovasEngine.OnComplete += results =>
            Dispatcher.Invoke(() => PopulateOvasResults(results));

        _ovasEngine.OnError += ex =>
            Dispatcher.Invoke(() =>
            {
                txtOvasStatus.Text = $"Error: {ex.Message}";
                MessageBox.Show(
                    $"OpenVAS scan failed:\n\n{ex.Message}\n\n" +
                    "Make sure:\n" +
                    "1. GVM/OpenVAS is running\n" +
                    "2. Host/port/credentials are correct\n" +
                    "3. Run: sudo systemctl start gvmd",
                    "OpenVAS Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            });

        await _ovasEngine.RunScanAsync(options);

        btnOvasScan.IsEnabled = true;
        btnOvasStop.IsEnabled = false;
        progressOvas.IsIndeterminate = false;
    }

    private void BtnOvasStop_Click(object sender, RoutedEventArgs e)
    {
        _ovasEngine?.Stop();
        txtOvasStatus.Text = "Stopping scan...";
        btnOvasStop.IsEnabled = false;
    }

    private void PopulateOvasResults(List<OpenVasResult> results)
    {
        _ovasResults.Clear();
        foreach (var result in results.OrderByDescending(r => r.CvssScore))
        {
            _ovasResults.Add(result);
        }

        ovasCritCount.Text = results.Count(r => r.Severity == "critical").ToString();
        ovasHighCount.Text = results.Count(r => r.Severity == "high").ToString();
        ovasMedCount.Text = results.Count(r => r.Severity == "medium").ToString();
        ovasLowCount.Text = results.Count(r => r.Severity == "low").ToString();
        ovasTotalCount.Text = results.Count.ToString();
    }

    private void GridOvasResults_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (gridOvasResults.SelectedItem is not OpenVasResult result)
        {
            ovasEmptyPanel.Visibility = Visibility.Visible;
            ovasDetailPanel.Visibility = Visibility.Collapsed;
            return;
        }

        ovasEmptyPanel.Visibility = Visibility.Collapsed;
        ovasDetailPanel.Visibility = Visibility.Visible;

        ovasDetailName.Text = result.Name;
        ovasDetailHost.Text = $"{result.Host}  ·  Port {result.Port}";

        var riskColor = (Color)ColorConverter.ConvertFromString(result.SeverityColor);
        ovasRiskBadge.Background = new SolidColorBrush(riskColor) { Opacity = 0.25 };
        ovasRiskBadge.BorderBrush = new SolidColorBrush(riskColor);
        ovasRiskLabel.Text = result.SeverityUpper;
        ovasCvssLabel.Text = result.CvssDisplay;

        ovasCveId.Text = string.IsNullOrWhiteSpace(result.CveId) ? "No CVE" : result.CveId;
        ovasFamilyName.Text = string.IsNullOrWhiteSpace(result.FamilyName) ? "Unknown family" : result.FamilyName;
        ovasDescription.Text = string.IsNullOrWhiteSpace(result.Description) ? "No description." : result.Description;
        ovasSolution.Text = string.IsNullOrWhiteSpace(result.Solution) ? "No remediation provided." : result.Solution;
        ovasNvtOid.Text = $"NVT OID: {result.NvtOid}\nhttps://www.openvas.org/";

        ovasDetailPanel.ScrollToTop();
    }

    private void BtnOvasExport_Click(object sender, RoutedEventArgs e)
    {
        if (_ovasResults.Count == 0)
        {
            txtOvasStatus.Text = "No OpenVAS results to export.";
            return;
        }

        var doc = new XDocument(
            new XElement("openvas_results",
                new XAttribute("target", txtOvasTarget.Text),
                new XAttribute("scan_time", DateTime.Now.ToString("o")),
                new XAttribute("total", _ovasResults.Count),
                _ovasResults.Select(r =>
                    new XElement("result",
                        new XAttribute("severity", r.Severity),
                        new XAttribute("cvss", r.CvssScore),
                        new XElement("name", r.Name),
                        new XElement("host", r.Host),
                        new XElement("port", r.Port),
                        new XElement("cve", r.CveId),
                        new XElement("description", r.Description),
                        new XElement("solution", r.Solution),
                        new XElement("nvt_oid", r.NvtOid)))));

        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"openvas_{DateTime.Now:yyyyMMdd_HHmm}.xml");

        doc.Save(path);
        MessageBox.Show(
            $"Exported {_ovasResults.Count} results to:\n{path}",
            "Export complete",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private OpenVasSettings GetOvasSettings()
    {
        return new OpenVasSettings
        {
            Host = txtOvasHost.Text.Trim(),
            Port = int.TryParse(txtOvasPort.Text, out var parsedPort) ? parsedPort : 9390,
            Username = txtOvasUser.Text.Trim(),
            Password = pwdOvas.Password,
            AcceptAllCerts = true
        };
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

public class ApplicationUiSettings
{
    public string DefaultTargetUrl { get; set; } = string.Empty;
    public bool DeepScanByDefault { get; set; }
    public int DefaultProxyPort { get; set; } = 8080;
    public string DefaultNmapTarget { get; set; } = string.Empty;
    public string DefaultNmapPorts { get; set; } = "1-1024";
    public string DefaultOvasHost { get; set; } = string.Empty;
    public int DefaultOvasPort { get; set; } = 9390;
    public string DefaultOvasUser { get; set; } = "admin";
    public string ThemeMode { get; set; } = "System default";
    public double TextFontSize { get; set; } = 13;
    public string TextStyle { get; set; } = "Default";
}