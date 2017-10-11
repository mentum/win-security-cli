
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Text;

namespace dpapi_cli {
    class Program {

        const int INPUT_STREAM_SIZE = 800 * 1024;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);
        
        private static string pCheck() {
            IntPtr tokenHandle;
            string userName;

            userName = Environment.UserName;

            const int LOGON32_PROVIDER_DEFAULT = 0;
            const int LOGON32_LOGON_INTERACTIVE = 2;

            // Call LogonUser to obtain a handle to an access token.
            bool loginSuccess = LogonUser(userName, null, "", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out tokenHandle);

            if(tokenHandle != IntPtr.Zero) {
                CloseHandle(tokenHandle);
            }

            int errorCode = Marshal.GetLastWin32Error();

            if (loginSuccess || errorCode == 1327)
            {
                return "false";
            } else {
                return "true";
            }
        }

        private static string ReadFullInput() {
            Stream inputStream = Console.OpenStandardInput(INPUT_STREAM_SIZE);
            byte[] bytes = new byte[INPUT_STREAM_SIZE];
            int length = inputStream.Read(bytes, 0, INPUT_STREAM_SIZE);
            
            return Encoding.UTF8.GetString(bytes, 0, length);
        }

        private static string Encrypt(byte[] entropy) {
            var inputString = ReadFullInput();
            var encryptedBytes = ProtectedData.Protect(Encoding.Unicode.GetBytes(inputString), entropy, DataProtectionScope.CurrentUser);

            return Convert.ToBase64String(encryptedBytes);
        }

        private static string Decrypt(byte[] entropy) {
            string rawString = ReadFullInput();

            var encryptedBytes = Convert.FromBase64String(rawString);
            var rawBytes = ProtectedData.Unprotect(encryptedBytes, entropy, DataProtectionScope.CurrentUser);
            return Encoding.Unicode.GetString(rawBytes, 0, rawBytes.Length);
        }

        private static void Error(string msg , Exception ex) {
            if (ex != null) {
                Console.WriteLine(ex.ToString());
            }
            Console.WriteLine(msg);
            Environment.Exit(1);
        }

        static void Main(string[] args) {
            string output = "Invalid Flag. Use 'd' for decryption, 'e' for encryption and 'p' to check if current user has a password set";
            byte[] entropy = null;

            if (args.Length < 1 || args.Length > 2) {
                Error("Invalid number of arguments.", null);
            }

            if (args.Length == 2) {
                try {
                    entropy = Convert.FromBase64String(args[1]);                
                } catch {
                    Error("Invalid base64 entropy", null);
                }
            }

            switch(args[0]) {
                case "e":

                    try {
                        output = Encrypt(entropy);
                    } catch {
                        Error("Encryption error.", null);
                    }

                    break;

                case "d":
                    try {
                        output = Decrypt(entropy);
                    } catch (Exception e) {
                        Error("Decryption Error.", e);
                    }
                    break;

                case "p":
                    try {
                        output = pCheck();
                    } catch {
                        Error("Password check error", null);
                    }
                    break;
            }

            Console.Write(output);
        }
    }
}
