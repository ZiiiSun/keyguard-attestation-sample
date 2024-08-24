// See https://aka.ms/new-console-template for more information
using keyguardsample;
using System.Security.Cryptography;
class TestApp
{
    static string keyName = "testKey";
    static async Task Main(string[] args)
    {
        Console.WriteLine("Getting attestationToken ... ");
        KeyGuardManager kgm = new KeyGuardManager();
        if (!kgm.TryCreateKeyMaterial(keyName, out CngKey cngKey))
        {
            Console.WriteLine("cngkey creation failed.");
        }

        kgm.IsKeyGuardProtected(cngKey);
        kgm.IsPerBootKey(cngKey);
        // create self-signed certificate
        CertificateManager.CreateSelfSignedCertificate(cngKey);

        AttestationResultErrorCode errorCode = AttestationClientLib.InitAttestationLib(AttestationLogFunction);
        if (errorCode != AttestationResultErrorCode.SUCCESS)
        {
            Console.WriteLine($"Failed to initialize {nameof(AttestationClientLib)}");
        }

        // get MAA endpoint
        string endpoint = await MAAManager.GetMAAEndPoint();
        errorCode = AttestationClientLib.AttestKeyGuardImportKey(endpoint, "", null, cngKey.Handle, "kg-sample-client", out string? attestationToken);
        if (errorCode != AttestationResultErrorCode.SUCCESS)
        {
            Console.WriteLine($"error in getting token {attestationToken}"); ;
        }
        else
        {
            Console.WriteLine($"got token {attestationToken}");
        }
    }

    private static void AttestationLogFunction(IntPtr ctx, string logTag, AttestationClientLib.LogLevel level, string function, int line, string message)
    {
        const string title = nameof(AttestationLogFunction) + ": {LogTag}, {Function}, {Line}, {Message}";
        if (level == AttestationClientLib.LogLevel.Error)
        {
            Console.WriteLine($"{title} - {level}: {logTag}, {function}, {line}, {message}");
        }
        else if (level == AttestationClientLib.LogLevel.Info)
        {
            Console.WriteLine($"{title}: {logTag}, {function}, {line}, {message}");
        }
        else if (level == AttestationClientLib.LogLevel.Warn)
        {
            Console.WriteLine($"{title}: {logTag}, {function}, {line}, {message}");
        }
        else if (level == AttestationClientLib.LogLevel.Debug)
        {
            Console.WriteLine($"{title}: {logTag}, {function}, {line}, {message}");
        }
        else
        {
            Console.WriteLine($"{title}: {logTag}, {function}, {line}, {message}");
        }
    }

    }