using HtmlAgilityPack;

namespace WebVulnScanner.Core.Scanner;

public static class Crawler
{
    public static IEnumerable<string> ExtractLinks(string html, string baseUrl)
    {
        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        var links = doc.DocumentNode.SelectNodes("//a[@href]");
        if (links is null)
        {
            yield break;
        }

        foreach (var link in links)
        {
            var href = link.GetAttributeValue("href", "");
            if (Uri.TryCreate(new Uri(baseUrl), href, out var absolute))
            {
                if (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)
                {
                    yield return absolute.ToString();
                }
            }
        }
    }
}
