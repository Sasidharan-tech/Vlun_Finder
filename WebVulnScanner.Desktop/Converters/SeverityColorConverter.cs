using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using WebVulnScanner.Core.Models;

namespace WebVulnScanner.Desktop.Converters;

public class SeverityColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int riskScore)
        {
            return riskScore switch
            {
                >= 75 => new SolidColorBrush(Colors.DarkRed),
                >= 50 => new SolidColorBrush(Colors.OrangeRed),
                >= 25 => new SolidColorBrush(Colors.Goldenrod),
                _ => new SolidColorBrush(Colors.ForestGreen)
            };
        }

        var severity = value switch
        {
            Severity s => s.ToString(),
            _ => value?.ToString() ?? ""
        };

        return severity switch
        {
            "Critical" => new SolidColorBrush(Colors.DarkRed),
            "High" => new SolidColorBrush(Colors.Red),
            "Medium" => new SolidColorBrush(Colors.Orange),
            "Low" => new SolidColorBrush(Colors.Green),
            _ => new SolidColorBrush(Colors.Gray)
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
