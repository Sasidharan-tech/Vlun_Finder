using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Collections;
using System.Net;
using System.Text;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;
using WebVulnScanner.Core.Models;

namespace WebVulnScanner.Core.Proxy;

public class InterceptingProxyServer : IDisposable
{
    private readonly ProxyServer _proxy = new();
    private readonly int _port;
    private int _requestCount;

    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingRequests = new();

    public bool IsIntercepting { get; set; } = true;
    public bool IsRunning { get; private set; }

    public ObservableCollection<ProxyRequestEntry> CapturedRequests { get; } = new();

    public event Action<ProxyRequestEntry>? OnRequestCaptured;
    public event Action<ProxyRequestEntry>? OnResponseCaptured;
    public event Action<string>? OnLog;

    public InterceptingProxyServer(int port = 8080)
    {
        _port = port;
    }

    public void Start()
    {
        if (IsRunning)
        {
            return;
        }

        _proxy.BeforeRequest += OnBeforeRequest;
        _proxy.BeforeResponse += OnBeforeResponse;
        _proxy.ServerCertificateValidationCallback += OnCertValidation;

        _proxy.CertificateManager.CreateRootCertificate(true);
        _proxy.CertificateManager.TrustRootCertificate(true);

        var endpoint = new ExplicitProxyEndPoint(IPAddress.Any, _port, decryptSsl: true);
        _proxy.AddEndPoint(endpoint);
        _proxy.Start();

        IsRunning = true;
        OnLog?.Invoke($"Proxy started on 127.0.0.1:{_port}");
    }

    public void Stop()
    {
        if (!IsRunning)
        {
            return;
        }

        _proxy.BeforeRequest -= OnBeforeRequest;
        _proxy.BeforeResponse -= OnBeforeResponse;
        _proxy.ServerCertificateValidationCallback -= OnCertValidation;
        _proxy.Stop();

        IsRunning = false;
        OnLog?.Invoke("Proxy stopped");
    }

    private async Task OnBeforeRequest(object sender, SessionEventArgs e)
    {
        var body = e.HttpClient.Request.HasBody
            ? await e.GetRequestBodyAsString()
            : "";

        var id = Guid.NewGuid().ToString();
        var entry = new ProxyRequestEntry
        {
            Id = id,
            Index = Interlocked.Increment(ref _requestCount),
            Method = e.HttpClient.Request.Method,
            Host = e.HttpClient.Request.RequestUri.Host,
            Url = e.HttpClient.Request.RequestUri.PathAndQuery,
            FullUrl = e.HttpClient.Request.Url,
            Headers = FormatHeaders(e.HttpClient.Request.Headers),
            Body = body,
            Timestamp = DateTime.Now,
            RawRequest = BuildRawRequest(e, body),
            IsIntercepted = IsIntercepting
        };

        CapturedRequests.Insert(0, entry);
        OnRequestCaptured?.Invoke(entry);

        if (!IsIntercepting)
        {
            return;
        }

        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[id] = tcs;
        entry.Tcs = tcs;

        var result = await tcs.Task;

        if (result == "DROP")
        {
            e.Ok("Request dropped by proxy interceptor.");
            return;
        }

        if (!string.IsNullOrWhiteSpace(result) && result != "FORWARD")
        {
            ApplyEditedRequest(e, result);
        }
    }

    private async Task OnBeforeResponse(object sender, SessionEventArgs e)
    {
        var entry = CapturedRequests.FirstOrDefault(r => r.FullUrl == e.HttpClient.Request.Url);
        if (entry is null)
        {
            return;
        }

        entry.StatusCode = e.HttpClient.Response.StatusCode;
        entry.ResponseHeaders = FormatHeaders(e.HttpClient.Response.Headers);

        if (e.HttpClient.Response.HasBody)
        {
            entry.ResponseBody = await e.GetResponseBodyAsString();
        }

        OnResponseCaptured?.Invoke(entry);
    }

    public void Forward(string requestId, string editedRaw)
    {
        if (_pendingRequests.TryRemove(requestId, out var tcs))
        {
            tcs.TrySetResult(string.IsNullOrWhiteSpace(editedRaw) ? "FORWARD" : editedRaw);
        }
    }

    public void Drop(string requestId)
    {
        if (_pendingRequests.TryRemove(requestId, out var tcs))
        {
            tcs.TrySetResult("DROP");
        }
    }

    public int ForwardAll()
    {
        var forwarded = 0;

        foreach (var pending in _pendingRequests)
        {
            if (_pendingRequests.TryRemove(pending.Key, out var tcs))
            {
                tcs.TrySetResult("FORWARD");
                forwarded++;
            }
        }

        return forwarded;
    }

    private Task OnCertValidation(object sender, CertificateValidationEventArgs e)
    {
        e.IsValid = true;
        return Task.CompletedTask;
    }

    private static string BuildRawRequest(SessionEventArgs e, string body)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{e.HttpClient.Request.Method} {e.HttpClient.Request.RequestUri.PathAndQuery} HTTP/1.1");
        foreach (var header in e.HttpClient.Request.Headers)
        {
            sb.AppendLine($"{header.Name}: {header.Value}");
        }

        if (!string.IsNullOrEmpty(body))
        {
            sb.AppendLine();
            sb.Append(body);
        }

        return sb.ToString();
    }

    private static void ApplyEditedRequest(SessionEventArgs e, string raw)
    {
        var lines = raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length == 0)
        {
            return;
        }

        var bodyStart = Array.FindIndex(lines, string.IsNullOrWhiteSpace);
        if (bodyStart >= 0 && bodyStart < lines.Length - 1)
        {
            var newBody = string.Join("\n", lines.Skip(bodyStart + 1));
            e.SetRequestBodyString(newBody);
        }
    }

    private static string FormatHeaders(IEnumerable headers)
    {
        var lines = new List<string>();
        foreach (var header in headers)
        {
            var type = header.GetType();
            var name = type.GetProperty("Name")?.GetValue(header)?.ToString() ?? "";
            var value = type.GetProperty("Value")?.GetValue(header)?.ToString() ?? "";
            lines.Add($"{name}: {value}");
        }

        return string.Join("\n", lines);
    }

    public void Dispose()
    {
        Stop();
    }
}
