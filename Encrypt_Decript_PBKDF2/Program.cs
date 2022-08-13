using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decript_PBKDF2
{
    public static class Program
    {
        static void Main(string[] args)
        {
            string password = "I am password";
            //string secret = Encrypt(password);

            //Console.WriteLine($"This is Hashed Password : \n {secret}");

            string encoding = EncryptService(password);
            string pas = DencryptService(encoding);
            Console.WriteLine($"UTF8 his is Hashed Password : \n {encoding}" + "\n");
            Console.WriteLine($"UTF8 This is From  Hashed Password : \n {pas}" + "\n");

            string encoding1 = EncryptService(password);
            string pas1 = DencryptService(encoding);
            Console.WriteLine($"ASCII This is Hashed Password : \n {encoding1}" + "\n");
            Console.WriteLine($"ASCII This is From  Hashed Password : \n {pas1}" + "\n");

            Console.ReadLine();
        }

        // Identity Encrypt. Decrypt not exist!!!
        public static string Encrypt(string data)
        {
            var fakeSalt = Encoding.ASCII.GetBytes("I am Secret password");

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: data,
                salt: fakeSalt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return hashed;
        }

        //MD5 is not advnced for work. 
        public static string EncryptService(string gelen)
        {
            string _res;
            string hash = "I am Secret password";
            byte[] data = Encoding.UTF8.GetBytes(gelen);

            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {

                byte[] keys = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(hash));

                using (TripleDESCryptoServiceProvider tr = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform cryptoTransform = tr.CreateEncryptor();
                    byte[] result = cryptoTransform.TransformFinalBlock(data, 0, data.Length);
                    _res = Convert.ToBase64String(result, 0, result.Length);
                }
            }
            return _res;

        }

        public static string DencryptService(string gelen)
        {
            string _res;
            string hash = "I am Secret password";
            byte[] data = Convert.FromBase64String(gelen);

            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {

                byte[] keys = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(hash));

                using (TripleDESCryptoServiceProvider tr = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform cryptoTransform = tr.CreateDecryptor();
                    byte[] result = cryptoTransform.TransformFinalBlock(data, 0, data.Length);
                    _res = Encoding.UTF8.GetString(result);
                }
            }
            return _res;
        }


        public static string EncryptServiceASCII(this string encrypt)
        {
            string _res;
            string hash = "I am Secret password";
            byte[] data = Encoding.ASCII.GetBytes(encrypt);

            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {

                byte[] keys = md5.ComputeHash(UTF8Encoding.ASCII.GetBytes(hash));

                using (TripleDESCryptoServiceProvider tr = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform cryptoTransform = tr.CreateEncryptor();
                    byte[] result = cryptoTransform.TransformFinalBlock(data, 0, data.Length);
                    _res = Convert.ToBase64String(result, 0, result.Length);
                }
            }
            return _res;

        }

        public static string DencryptServiceASCII(string gelen)
        {
            string _res;
            string hash = "I am Secret password";
            byte[] data = Convert.FromBase64String(gelen);

            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {

                byte[] keys = md5.ComputeHash(UTF8Encoding.ASCII.GetBytes(hash));

                using (TripleDESCryptoServiceProvider tr = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform cryptoTransform = tr.CreateDecryptor();
                    byte[] result = cryptoTransform.TransformFinalBlock(data, 0, data.Length);
                    _res = Encoding.ASCII.GetString(result);
                }
            }
            return _res;
        }
    }
}
