using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WebVulnScanner.Core.Proxy;

public static class CertificateGenerator
{
    private const string CaName = "WebVulnScanner CA";
    private static X509Certificate2? _rootCa;

    public static void Initialize()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var certs = store.Certificates.Find(X509FindType.FindBySubjectName, CaName, false);

        if (certs.Count > 0)
        {
            _rootCa = certs[0];
        }
        else
        {
            _rootCa = GenerateCaCertificate();
            InstallCertificate(_rootCa);
        }
    }

    public static X509Certificate2 GetCertificate(string hostname)
    {
        if (_rootCa is null)
        {
            Initialize();
        }

        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest(
            $"CN={hostname}, O=WebVulnScanner",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(hostname);
        request.CertificateExtensions.Add(sanBuilder.Build());

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") },
                false));

        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);

        var cert = request.Create(
            _rootCa!,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365),
            serialNumber);

        return cert.CopyWithPrivateKey(rsa);
    }

    private static X509Certificate2 GenerateCaCertificate()
    {
        using var rsa = RSA.Create(4096);

        var request = new CertificateRequest(
            $"CN={CaName}, O=WebVulnScanner, C=US",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        return new X509Certificate2(cert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.Exportable);
    }

    private static void InstallCertificate(X509Certificate2 cert)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
    }
}
