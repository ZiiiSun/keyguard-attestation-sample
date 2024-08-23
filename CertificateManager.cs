using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal class CertificateManager
{
    public static X509Certificate2 CreateSelfSignedCertificate(CngKey key)
    {
        var subjectName = new X500DistinguishedName("CN=zzzSelfSignedCert");

        var request = new CertificateRequest(subjectName, new RSACng(key), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add basic extensions
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true)); // in X.509 certificates, it represents for Enhanced Key Usage (EKU) extension

        // Create a self-signed certificate
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));

        StoreCertificate(certificate);
        return certificate;
    }
    public static void StoreCertificate(X509Certificate2 certificate)
    {
        using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();
        }
    }

}
