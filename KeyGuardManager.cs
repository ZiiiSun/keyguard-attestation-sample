using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.PlatformsCommon.Interfaces;

internal class KeyGuardManager
{
    // The name of the key guard isolation property
    private const string IsKeyGuardEnabledProperty = "Virtual Iso";

    // The flag for using virtual isolation with CNG keys
    private const CngKeyCreationOptions NCryptUseVirtualIsolationFlag = (CngKeyCreationOptions)0x00020000;
    private const CngKeyCreationOptions NCryptUsePerBootKeyFlag = (CngKeyCreationOptions)0x00040000;

    // Constants specifying the names for the key storage provider and key names
    private const string KeyProviderName = "Microsoft Software Key Storage Provider";
    private const string MachineKeyName = "ManagedIdentityCredentialKey";
    private const string SoftwareKeyName = "ResourceBindingKey";
    private const string KeyGuardKeyName = "ManagedIdentityUserBindingKey";

    /// <summary>
    /// cryptographic key type
    /// </summary>
    // public CryptoKeyType CryptoKeyType { get; private set; } = CryptoKeyType.None;

    /// <summary>
    /// Loads a CngKey with the given key provider.
    /// </summary>
    /// <param name="keyProvider"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public CngKey LoadCngKeyWithProvider(string keyProvider)
    {
        try
        {
            Console.WriteLine("Initializing Cng Key.");

            // Try to get the key material from machine key
            if (TryGetKeyMaterial(KeyProviderName, MachineKeyName, CngKeyOpenOptions.MachineKey, out CngKey cngKey))
            {
                Console.WriteLine($"A machine key was found. Key Name : {MachineKeyName}. ");
                return cngKey;
            }

            // If machine key is not available, fall back to software key
            if (TryGetKeyMaterial(KeyProviderName, SoftwareKeyName, CngKeyOpenOptions.None, out cngKey))
            {
                Console.WriteLine($"A non-machine key was found. Key Name : {SoftwareKeyName}. ");
                return cngKey;
            }

            Console.WriteLine("Machine / Software keys are not setup. " +
                "Attempting to create a new key for Managed Identity.");

            // Attempt to create a new key if none are available
            if (TryCreateKeyMaterial(KeyGuardKeyName, out cngKey))
            {
                return cngKey;
            }

            // All attempts for getting keys failed
            // Now we should follow the legacy managed identity flow
            Console.WriteLine($"Machine / Software keys are not setup. " +
                "Proceed to check for legacy managed identity sources.");

            return null;
        }
        catch (Exception ex)
        {
            // Log the exception or handle it according to your error policy
            throw new InvalidOperationException("Failed to load CngKey.", ex);
        }
    }
    /// <summary>
    /// Attempts to retrieve cryptographic key material for a specified key name and provider.
    /// </summary>
    /// <param name="keyProviderName">The name of the key provider.</param>
    /// <param name="keyName">The name of the key.</param>
    /// <param name="cngKeyOpenOptions">The options for opening the CNG key.</param>
    /// <param name="ecdsaKey">The resulting key material.</param>
    /// <returns>
    ///   <c>true</c> if the key material is successfully retrieved; otherwise, <c>false</c>.
    /// </returns>
    public bool TryGetKeyMaterial(
        string keyProviderName,
        string keyName,
        CngKeyOpenOptions cngKeyOpenOptions,
        out CngKey cngKey)
    {
        try
        {
            // Specify the optional flags for opening the key
            CngKeyOpenOptions options = cngKeyOpenOptions;
            options |= CngKeyOpenOptions.Silent;

            // Open the key with the specified options
            cngKey = CngKey.Open(keyName, new CngProvider(keyProviderName), options);
            //ecdsaKey = new cngKey(cngKey);
            return true;
        }
        catch (CryptographicException ex)
        {
            // Check if the error message contains "Keyset does not exist"
            if (ex.Message.IndexOf("Keyset does not exist", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Console.WriteLine($"Key with name : {keyName} does not exist.");
            }
            else
            {
                // Handle other cryptographic errors
                Console.WriteLine($"Exception caught during key operations. " +
                $"Error Mesage : {ex.Message}.");
            }
        }

        cngKey = null;
        return false;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

    /// <summary>
    /// Attempts to create a new cryptographic key and load it into a CngKey with the specified options.
    /// </summary>
    /// <param name="keyName">The name of the key to create.</param>
    /// <param name="ecdsaKey">Output parameter that returns the created ECDsa key, if successful.</param>
    /// <returns>True if the key was created and loaded successfully, false otherwise.</returns>
    public bool TryCreateKeyMaterial(string keyName, out CngKey cngKey)
    {
        cngKey = null;

        try
        {
            var keyParams = new CngKeyCreationParameters
            {
                KeyUsage = CngKeyUsages.AllUsages,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                KeyCreationOptions = NCryptUseVirtualIsolationFlag | NCryptUsePerBootKeyFlag |  CngKeyCreationOptions.OverwriteExistingKey | CngKeyCreationOptions.MachineKey ,
                ExportPolicy = CngExportPolicies.None // set the key to non-exportable
            };

            // set the length of the key to 2048
            keyParams.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None)); // Set the key size to 2048 bits

            cngKey = CngKey.Create(CngAlgorithm.Rsa, keyName, keyParams);
            
            Console.WriteLine($"Key '{keyName}' created successfully with Virtual Isolation.");
            return true; // Key creation was successful
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to create user key '{keyName}': {ex.Message}");
            return false; // Key creation failed
        }
    }

    /// <summary>
    /// Checks if the specified CNG key is protected by KeyGuard.
    /// </summary>
    /// <param name="cngKey">The CNG key to check for KeyGuard protection.</param>
    /// <returns>
    ///   <c>true</c> if the key is protected by KeyGuard; otherwise, <c>false</c>.
    /// </returns>
    public bool IsKeyGuardProtected(CngKey cngKey)
    {
        //Check to see if the KeyGuard Isolation flag was set in the key
        if (!cngKey.HasProperty(IsKeyGuardEnabledProperty, CngPropertyOptions.None))
        {
            return false;
        }

        //if key guard isolation flag exist, check for the key guard property value existence
        CngProperty property = cngKey.GetProperty(IsKeyGuardEnabledProperty, CngPropertyOptions.None);

        // Retrieve the key guard property value
        var keyGuardProperty = property.GetValue();

        // Check if the key guard property exists and has a non-zero value
        if (keyGuardProperty != null && keyGuardProperty.Length > 0)
        {
            if (keyGuardProperty[0] != 0)
            {
                // KeyGuard key is available; set the cryptographic key type accordingly
                Console.WriteLine("The key is under keyguard protection. ");
                return true;
            }
        }

        // KeyGuard key is not available

        Console.WriteLine("KeyGuard in the current key is NOT available. ");
        return false;
    }


    public void IsPerBootKey(CngKey cngKey)
    {
        //NCryptUsePerBootKeyFlag
        if (!cngKey.HasProperty("Per Boot Key", CngPropertyOptions.None))
        {
            Console.WriteLine("NOT perboot key.");
            return;
        }
        CngProperty property = cngKey.GetProperty("Per Boot Key", CngPropertyOptions.None);

        // Retrieve the key guard property value
        var keyGuardProperty = property.GetValue();

        // Check if the key guard property exists and has a non-zero value
        if (keyGuardProperty != null && keyGuardProperty.Length > 0)
        {
            if (keyGuardProperty[0] != 0)
            {
                // KeyGuard key is available; set the cryptographic key type accordingly
                Console.WriteLine("Yes Perbootkey ");
                return;
            }
        }

        Console.WriteLine("NOT perboot key.");
    }
}
