using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal class CertificateManager
{
    public static X509Certificate2 CreateSelfSignedCertificate(CngKey key)
    {
        var subjectName = new X500DistinguishedName("CN=zzzSelfSignedCert");

        var request = new CertificateRequest(subjectName, new RSACng(key), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

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
