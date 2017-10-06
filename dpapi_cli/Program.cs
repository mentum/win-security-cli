
using System;
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
            //This parameter causes LogonUser to create a primary token.
            const int LOGON32_LOGON_INTERACTIVE = 2;

            // Call LogonUser to obtain a handle to an access token.
            bool loginSuccess = LogonUser(userName, null, "",
                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                out tokenHandle);

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

        private static string Encrypt() {
            var inputString = Console.ReadLine();
            var encryptedBytes = ProtectedData.Protect(Encoding.Unicode.GetBytes(inputString), null, DataProtectionScope.CurrentUser);

            var encodedString = Convert.ToBase64String(encryptedBytes);

            return encodedString;
        }

        private static string Decrypt() {
            var rawString = Console.ReadLine();
            var encryptedBytes = Convert.FromBase64String(rawString);
            var rawBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.CurrentUser);

            return Encoding.Unicode.GetString(rawBytes);
        }

        private static void Error(string msg) {
            Console.WriteLine(msg);
            Environment.Exit(1);
        }

        static void Main(string[] args) {

            string output = "Invalid Flag. Use 'd' for decryption or 'e' for encryption";

            if (args.Length != 1) {
                Error("Invalid number of arguments.");
            }

            switch(args[0]) {
                case "e":

                    try {
                        output = Encrypt();
                    } catch {
                        Error("Encryption error.");
                    }

                    break;

                case "d":
                    try {
                        output = Decrypt();
                    } catch {
                        Error("Decryption Error.");
                    }
                    break;

                case "p":
                    try {
                        output = pCheck();
                    } catch {
                        Error("Password check error");
                    }
                    break;
            }

            Console.Write(output);
        }
    }
}
