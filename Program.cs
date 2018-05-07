using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.EntityFrameworkCore;


namespace bruteforcer
{
    class Program
    {
        public static string path;

        static void Main(string[] args)
        {
            // Load Password File
            var wrongPasswords = JsonConvert.DeserializeObject<Dictionary<string, bool>>(File.ReadAllText("wrongPasswords.json"));
            // Set path from args
            path = args[0];

            bool passwordFound = false;
            // Load PasswordHash
            byte[] passwordHash = LoadStoredData("PasswordHash");

            string password = "";
            while(!passwordFound) {
                if(!wrongPasswords.ContainsKey(password)) {
                    if (passwordHash != null && !passwordHash.SequenceEqual(password.ToAesKey().Sha256())) {
                        Console.WriteLine("Wrong Password: " + password);
                        wrongPasswords.Add(password, true);
                    } else {
                        Console.WriteLine("Password Found: " + password);
                        passwordFound = true;
                    }
                } else {
                    Console.WriteLine("Skipping Password: " + password);
                }
                
            }
            
            

            // Write Password File
            File.WriteAllText("wrongPasswords.json", JsonConvert.SerializeObject(wrongPasswords));
        }

        private static byte[] LoadStoredData(string name)
        {
            using (WalletDataContext ctx = new WalletDataContext(path))
            {
                return ctx.Keys.FirstOrDefault(p => p.Name == name)?.Value;
            }
        }



    }
    public static class Helper {
        private static ThreadLocal<SHA256> _sha256 = new ThreadLocal<SHA256>(() => SHA256.Create());

        public static byte[] Sha256(this IEnumerable<byte> value)
        {
            return _sha256.Value.ComputeHash(value.ToArray());
        }
        public static byte[] Sha256(this byte[] value, int offset, int count)
        {
            return _sha256.Value.ComputeHash(value, offset, count);
        }

        internal static byte[] ToAesKey(this string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] passwordHash = sha256.ComputeHash(passwordBytes);
                byte[] passwordHash2 = sha256.ComputeHash(passwordHash);
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
                Array.Clear(passwordHash, 0, passwordHash.Length);
                return passwordHash2;
            }
        }

        internal static byte[] ToAesKey(this SecureString password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] passwordBytes = password.ToArray();
                byte[] passwordHash = sha256.ComputeHash(passwordBytes);
                byte[] passwordHash2 = sha256.ComputeHash(passwordHash);
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
                Array.Clear(passwordHash, 0, passwordHash.Length);
                return passwordHash2;
            }
        }

        internal static byte[] ToArray(this SecureString s)
        {
            if (s == null)
                throw new NullReferenceException();
            if (s.Length == 0)
                return new byte[0];
            List<byte> result = new List<byte>();
            IntPtr ptr = SecureStringMarshal.SecureStringToGlobalAllocAnsi(s);
            try
            {
                int i = 0;
                do
                {
                    byte b = Marshal.ReadByte(ptr, i++);
                    if (b == 0)
                        break;
                    result.Add(b);
                } while (true);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(ptr);
            }
            return result.ToArray();
        }
    }
}
