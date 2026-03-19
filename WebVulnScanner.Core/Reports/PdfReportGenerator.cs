using iTextSharp.text;
using iTextSharp.text.pdf;
using WebVulnScanner.Core.Models;

namespace WebVulnScanner.Core.Reports;

public static class PdfReportGenerator
{
    public static string Generate(ScanResult result, string? outputDirectory = null)
    {
        outputDirectory ??= Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        Directory.CreateDirectory(outputDirectory);

        var filePath = Path.Combine(outputDirectory, $"WebVulnScanner-Report-{DateTime.Now:yyyyMMdd-HHmmss}.pdf");

        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);
        var document = new Document(PageSize.A4, 36, 36, 36, 36);
        PdfWriter.GetInstance(document, fs);
        document.Open();

        var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 18);
        var headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 12);
        var normalFont = FontFactory.GetFont(FontFactory.HELVETICA, 10);

        document.Add(new Paragraph("Web Vulnerability Scan Report", titleFont));
        document.Add(new Paragraph($"Target: {result.TargetUrl}", normalFont));
        document.Add(new Paragraph($"Date: {result.ScanDate:yyyy-MM-dd HH:mm:ss}", normalFont));
        document.Add(new Paragraph($"Pages Scanned: {result.PagesScanned}", normalFont));
        document.Add(new Paragraph($"Risk Score: {result.RiskScore}/100", normalFont));
        document.Add(new Paragraph(" "));

        document.Add(new Paragraph("Findings", headerFont));
        document.Add(new Paragraph(" "));

        var table = new PdfPTable(5) { WidthPercentage = 100 };
        table.SetWidths([1.2f, 1.6f, 2.6f, 3.2f, 3.2f]);

        AddCell(table, "Severity", headerFont);
        AddCell(table, "Type", headerFont);
        AddCell(table, "URL", headerFont);
        AddCell(table, "Description", headerFont);
        AddCell(table, "Remediation", headerFont);

        foreach (var finding in result.Vulnerabilities)
        {
            AddCell(table, finding.Severity.ToString(), normalFont);
            AddCell(table, finding.Type, normalFont);
            AddCell(table, finding.Url, normalFont);
            AddCell(table, finding.Description, normalFont);
            AddCell(table, finding.Remediation, normalFont);
        }

        document.Add(table);
        document.Close();

        return filePath;
    }

    private static void AddCell(PdfPTable table, string text, Font font)
    {
        var cell = new PdfPCell(new Phrase(text, font))
        {
            Padding = 6,
            VerticalAlignment = Element.ALIGN_MIDDLE
        };
        table.AddCell(cell);
    }
}
