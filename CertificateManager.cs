using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal class CertificateManager
{
    static readonly string certSubject = "CN=zzzSelfSignedCert";
    static readonly StoreLocation storeLocation = StoreLocation.LocalMachine;
    static readonly StoreName storeName = StoreName.My;

    public static X509Certificate2 CreateSelfSignedCertificate(CngKey key)
    {
        RemoveOldCert();
        var subjectName = new X500DistinguishedName(certSubject);

        var request = new CertificateRequest(subjectName, new RSACng(key), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Create a self-signed certificate
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));

        StoreCertificate(certificate);
        return certificate;
    }
    public static void StoreCertificate(X509Certificate2 certificate)
    {
        using (var store = new X509Store(storeName, storeLocation))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();
        }
    }

    private static void RemoveOldCert()
    {
        using (var store = new X509Store(storeName, storeLocation))
        {
            store.Open(OpenFlags.ReadWrite); // Open the store in read/write mode

            // Check if the certificate already exists
            // Find all certificates with the specified subject name
            var certsToRemove = store.Certificates
                .Cast<X509Certificate2>()
                .Where(c => c.Subject.Equals(certSubject, StringComparison.OrdinalIgnoreCase))
                .ToList(); // Convert to list to iterate and remove

            // Remove all matching certificates
            foreach (var cert in certsToRemove)
            {
                Console.WriteLine($"Removing certificate: {cert.Subject}");
                store.Remove(cert);
            }

            Console.WriteLine($"Removed {certsToRemove.Count} certificates with subject: {certSubject}");
        }
    }
}
