using System.ComponentModel;

namespace WebVulnScanner.Core.Models;

public class ProxyRequestEntry : INotifyPropertyChanged
{
    private int _statusCode;
    private string _responseHeaders = "";
    private string _responseBody = "";

    public string Id { get; set; } = Guid.NewGuid().ToString();
    public int Index { get; set; }
    public string Method { get; set; } = "";
    public string Host { get; set; } = "";
    public string Url { get; set; } = "";
    public string FullUrl { get; set; } = "";
    public string Headers { get; set; } = "";
    public string Body { get; set; } = "";
    public string RawRequest { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public bool IsIntercepted { get; set; }

    public int StatusCode
    {
        get => _statusCode;
        set
        {
            if (_statusCode == value) return;
            _statusCode = value;
            OnPropertyChanged(nameof(StatusCode));
        }
    }

    public string ResponseHeaders
    {
        get => _responseHeaders;
        set
        {
            if (_responseHeaders == value) return;
            _responseHeaders = value;
            OnPropertyChanged(nameof(ResponseHeaders));
        }
    }

    public string ResponseBody
    {
        get => _responseBody;
        set
        {
            if (_responseBody == value) return;
            _responseBody = value;
            OnPropertyChanged(nameof(ResponseBody));
        }
    }

    public TaskCompletionSource<string>? Tcs { get; set; }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
