using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// https://msazure.visualstudio.com/One/_git/Azure-LinuxPlatformIntegrity?path=/Attestation/AttestationClient/kglib/include/AttestationApi.h&_a=contents&version=GBmaster
internal static class AttestationClientLib
{
    public enum LogLevel
    {
        Error,
        Warn,
        Info,
        Debug,
    }

    public delegate void AttestationLogFunc(
        IntPtr ctx,
        string log_tag,
        LogLevel level,
        string function,
        int line,
        string message);

    // https://msazure.visualstudio.com/One/_git/Azure-LinuxPlatformIntegrity?path=/Attestation/AttestationClient/kglib/include/AttestationLogInfo.h&_a=contents&version=GBmaster
    [StructLayout(LayoutKind.Sequential)]
    public struct AttestationLogInfo
    {
        [MarshalAs(UnmanagedType.FunctionPtr)]
        public AttestationLogFunc Log;
        public IntPtr Ctx;
    }

    [DllImport("AttestationClientLib.dll", CharSet = CharSet.Unicode)]
    private static extern AttestationResultErrorCode InitAttestationLib(
        ref AttestationLogInfo attestationLogInfo);

    public static AttestationResultErrorCode InitAttestationLib(
        AttestationLogFunc attestationLogFunc)
    {
        LogCallBack = attestationLogFunc;

        LogInfo = new AttestationClientLib.AttestationLogInfo
        {
            Ctx = IntPtr.Zero,
            Log = LogCallBack
        };

        return InitAttestationLib(ref LogInfo);
    }

    [DllImport("AttestationClientLib.dll", CharSet = CharSet.Unicode)]
    private static extern AttestationResultErrorCode AttestKeyGuardImportKey(
            IntPtr attestationEndpoint,
            IntPtr authToken,
            IntPtr clientPayload,
            SafeNCryptKeyHandle importKeyHandle,
            out IntPtr attestationToken,
            IntPtr clientId);

    public static AttestationResultErrorCode AttestKeyGuardImportKey(
        string attestationEndpoint,
        string? authToken,
        string? clientPayload,
        SafeNCryptKeyHandle importKeyHandle,
        string clientId,
        out string? attestationToken)
    {
        IntPtr attestationEndpointPtr = Marshal.StringToHGlobalAnsi(attestationEndpoint);
        IntPtr authTokenPtr = Marshal.StringToHGlobalAnsi(authToken);
        IntPtr clientPayloadPtr = Marshal.StringToHGlobalAnsi(clientPayload);
        IntPtr clientIdPtr = Marshal.StringToHGlobalAnsi(clientId);
        IntPtr attestationTokenPtr = IntPtr.Zero;
        try
        {
            AttestationResultErrorCode ret = AttestKeyGuardImportKey(attestationEndpointPtr, authTokenPtr, clientPayloadPtr, importKeyHandle, out attestationTokenPtr, clientIdPtr);
            attestationToken = Marshal.PtrToStringAnsi(attestationTokenPtr);
            return ret;
        }
        finally
        {
            Marshal.FreeHGlobal(attestationEndpointPtr);
            Marshal.FreeHGlobal(authTokenPtr);
            Marshal.FreeHGlobal(clientPayloadPtr);
            Marshal.FreeHGlobal(clientIdPtr);
            FreeAttestationToken(attestationTokenPtr);
        }
    }

    [DllImport("AttestationClientLib.dll", CharSet = CharSet.Unicode)]
    public static extern void FreeAttestationToken(
        IntPtr attestationTokenPtr);

    [DllImport("AttestationClientLib.dll", CharSet = CharSet.Unicode)]
    public static extern void UninitAttestationLib();

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public static AttestationLogFunc LogCallBack;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

    public static AttestationLogInfo LogInfo;
}
