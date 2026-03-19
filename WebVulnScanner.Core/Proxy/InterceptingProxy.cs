using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using WebVulnScanner.Core.Models;

namespace WebVulnScanner.Core.Proxy;

public class InterceptingProxy : IDisposable
{
    private TcpListener? _listener;
    private readonly CancellationTokenSource _cts = new();
    private bool _interceptMode = true;
    private InterceptedRequest? _pendingRequest;
    private TaskCompletionSource<bool> _userActionTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public bool IsRunning { get; private set; }
    public int Port { get; set; } = 8080;

    public event EventHandler<InterceptedRequest>? RequestCaptured;
    public event EventHandler<string>? LogMessage;

    public void Start()
    {
        CertificateGenerator.Initialize();

        _listener = new TcpListener(IPAddress.Parse("127.0.0.1"), Port);
        _listener.Start();
        IsRunning = true;

        LogMessage?.Invoke(this, $"Proxy started on 127.0.0.1:{Port}");
        _ = Task.Run(() => AcceptConnections(_cts.Token));
    }

    private async Task AcceptConnections(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && IsRunning)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Accept error: {ex.Message}");
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            {
                var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);

                var requestLine = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(requestLine))
                {
                    return;
                }

                if (requestLine.StartsWith("CONNECT", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleHttpsConnect(client, requestLine, ct);
                }
                else
                {
                    await HandleHttpRequest(client, requestLine, reader, ct);
                }
            }
        }
        catch (Exception ex)
        {
            LogMessage?.Invoke(this, $"Client handler error: {ex.Message}");
        }
    }

    private async Task HandleHttpsConnect(TcpClient client, string requestLine, CancellationToken ct)
    {
        var match = Regex.Match(requestLine, @"CONNECT\s+([^:]+):(\d+)\s+HTTP/1\.[01]", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            return;
        }

        var host = match.Groups[1].Value;
        var port = int.Parse(match.Groups[2].Value);

        var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        await client.GetStream().WriteAsync(response, ct);

        var cert = CertificateGenerator.GetCertificate(host);
        using var sslClientStream = new SslStream(client.GetStream(), false);
        await sslClientStream.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12 | SslProtocols.Tls13, false);

        using var serverClient = new TcpClient();
        await serverClient.ConnectAsync(host, port, ct);
        using var sslServerStream = new SslStream(serverClient.GetStream(), false, (_, _, _, _) => true);
        await sslServerStream.AuthenticateAsClientAsync(host);

        await Task.WhenAny(
            HandleSslClientToServer(sslClientStream, sslServerStream, host, ct),
            HandleSslServerToClient(sslServerStream, sslClientStream, ct));
    }

    private async Task HandleSslClientToServer(Stream clientStream, Stream serverStream, string host, CancellationToken ct)
    {
        var buffer = new byte[8192];
        var requestBuilder = new StringBuilder();
        var headersComplete = false;

        while (!ct.IsCancellationRequested)
        {
            var read = await clientStream.ReadAsync(buffer, ct);
            if (read == 0)
            {
                break;
            }

            if (!headersComplete)
            {
                var text = Encoding.UTF8.GetString(buffer, 0, read);
                requestBuilder.Append(text);

                if (requestBuilder.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    headersComplete = true;
                    var rawRequest = requestBuilder.ToString();
                    var request = ParseRequest(rawRequest, true);
                    request.Host = host;

                    if (_interceptMode)
                    {
                        _pendingRequest = request;
                        RequestCaptured?.Invoke(this, request);
                        await WaitForUserAction();

                        if (request.Dropped)
                        {
                            return;
                        }

                        rawRequest = RebuildRequest(request);
                        var modifiedBytes = Encoding.UTF8.GetBytes(rawRequest);
                        await serverStream.WriteAsync(modifiedBytes, ct);
                    }
                    else
                    {
                        await serverStream.WriteAsync(buffer.AsMemory(0, read), ct);
                    }
                }
            }
            else
            {
                await serverStream.WriteAsync(buffer.AsMemory(0, read), ct);
            }
        }
    }

    private static async Task HandleSslServerToClient(Stream serverStream, Stream clientStream, CancellationToken ct)
    {
        var buffer = new byte[8192];
        while (!ct.IsCancellationRequested)
        {
            var read = await serverStream.ReadAsync(buffer, ct);
            if (read == 0)
            {
                break;
            }

            await clientStream.WriteAsync(buffer.AsMemory(0, read), ct);
        }
    }

    private async Task HandleHttpRequest(TcpClient client, string requestLine, StreamReader reader, CancellationToken ct)
    {
        var request = await ParseHttpRequestAsync(requestLine, reader);

        if (_interceptMode)
        {
            _pendingRequest = request;
            RequestCaptured?.Invoke(this, request);

            await WaitForUserAction();
            if (request.Dropped)
            {
                return;
            }
        }

        await ForwardHttpRequest(client, request, ct);
    }

    private static async Task<InterceptedRequest> ParseHttpRequestAsync(string requestLine, StreamReader reader)
    {
        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var method = parts[0];
        var url = parts[1];

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? line;
        while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync()))
        {
            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                headers[line[..colonIndex]] = line[(colonIndex + 1)..].Trim();
            }
        }

        var body = "";
        if (headers.TryGetValue("Content-Length", out var lenStr) && int.TryParse(lenStr, out var contentLength) && contentLength > 0)
        {
            var buffer = new char[contentLength];
            await reader.ReadBlockAsync(buffer, 0, contentLength);
            body = new string(buffer);
        }

        return new InterceptedRequest
        {
            Method = method,
            Url = url,
            Headers = headers,
            Body = body,
            RawRequest = $"{requestLine}\r\n{string.Join("\r\n", headers.Select(h => $"{h.Key}: {h.Value}"))}\r\n\r\n{body}",
            Timestamp = DateTime.Now
        };
    }

    private static InterceptedRequest ParseRequest(string rawRequest, bool isHttps)
    {
        var lines = rawRequest.Split(["\r\n"], StringSplitOptions.None);
        var firstLine = lines[0];
        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var i = 1;
        for (; i < lines.Length; i++)
        {
            if (string.IsNullOrEmpty(lines[i]))
            {
                break;
            }

            var colonIndex = lines[i].IndexOf(':');
            if (colonIndex > 0)
            {
                headers[lines[i][..colonIndex]] = lines[i][(colonIndex + 1)..].Trim();
            }
        }

        var body = string.Join("\r\n", lines.Skip(i + 1));
        var host = headers.GetValueOrDefault("Host", "unknown");
        var path = parts.Length > 1 ? parts[1] : "/";

        return new InterceptedRequest
        {
            Method = parts[0],
            Url = (isHttps ? "https://" : "http://") + host + path,
            Headers = headers,
            Body = body,
            RawRequest = rawRequest,
            Timestamp = DateTime.Now
        };
    }

    private static string RebuildRequest(InterceptedRequest request)
    {
        var uri = Uri.TryCreate(request.Url, UriKind.Absolute, out var parsed) ? parsed : null;
        var pathAndQuery = uri?.PathAndQuery ?? "/";

        var sb = new StringBuilder();
        sb.Append($"{request.Method} {pathAndQuery} HTTP/1.1\r\n");
        foreach (var header in request.Headers)
        {
            sb.Append($"{header.Key}: {header.Value}\r\n");
        }

        sb.Append("\r\n");
        sb.Append(request.Body);
        return sb.ToString();
    }

    private static async Task ForwardHttpRequest(TcpClient client, InterceptedRequest request, CancellationToken ct)
    {
        try
        {
            using var handler = new HttpClientHandler();
            using var httpClient = new HttpClient(handler);

            foreach (var header in request.Headers)
            {
                if (!header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase) &&
                    !header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            using var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Url);
            if (!string.IsNullOrEmpty(request.Body) && (request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) || request.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase) || request.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase)))
            {
                message.Content = new StringContent(request.Body, Encoding.UTF8);
            }

            using var response = await httpClient.SendAsync(message, ct);
            var responseBytes = await response.Content.ReadAsByteArrayAsync(ct);

            using var stream = client.GetStream();
            var statusLine = Encoding.UTF8.GetBytes($"HTTP/1.1 {(int)response.StatusCode} {response.StatusCode}\r\n");
            await stream.WriteAsync(statusLine, ct);

            foreach (var header in response.Headers)
            {
                var line = Encoding.UTF8.GetBytes($"{header.Key}: {string.Join(", ", header.Value)}\r\n");
                await stream.WriteAsync(line, ct);
            }

            foreach (var header in response.Content.Headers)
            {
                var line = Encoding.UTF8.GetBytes($"{header.Key}: {string.Join(", ", header.Value)}\r\n");
                await stream.WriteAsync(line, ct);
            }

            await stream.WriteAsync(Encoding.UTF8.GetBytes("\r\n"), ct);
            await stream.WriteAsync(responseBytes, ct);
        }
        catch
        {
        }
    }

    public void ForwardCurrentRequest()
    {
        if (_pendingRequest is null)
        {
            return;
        }

        _pendingRequest.Dropped = false;
        _userActionTcs.TrySetResult(true);
    }

    public void DropCurrentRequest()
    {
        if (_pendingRequest is null)
        {
            return;
        }

        _pendingRequest.Dropped = true;
        _userActionTcs.TrySetResult(true);
    }

    public void SetInterceptMode(bool enabled)
    {
        _interceptMode = enabled;
    }

    private async Task WaitForUserAction()
    {
        _userActionTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        await _userActionTcs.Task;
    }

    public void Stop()
    {
        IsRunning = false;
        _cts.Cancel();
        _listener?.Stop();
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
