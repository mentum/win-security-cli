using System;
using System.Security.Cryptography;
using System.Text;

namespace dpapi_cli {
    class Program {

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
            }

            Console.Write(output);
        }
    }
}
