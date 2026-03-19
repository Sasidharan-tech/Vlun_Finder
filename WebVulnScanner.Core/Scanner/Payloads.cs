namespace WebVulnScanner.Core.Scanner;

public static class Payloads
{
    public static readonly IReadOnlyList<string> XssPayloads =
    [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>"
    ];

    public static readonly IReadOnlyList<string> SqlPayloads =
    [
        "' OR '1'='1",
        "1 OR 1=1--"
    ];
}
