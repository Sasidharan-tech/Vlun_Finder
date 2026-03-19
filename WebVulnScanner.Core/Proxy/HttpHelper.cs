using System.Net.Http.Headers;

namespace WebVulnScanner.Core.Proxy;

public static class HttpHelper
{
    public static HttpClient CreateHttpClient(bool ignoreCertErrors = false)
    {
        var handler = new HttpClientHandler();
        if (ignoreCertErrors)
        {
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        var client = new HttpClient(handler);
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("WebVulnScanner", "1.0"));
        return client;
    }
}
