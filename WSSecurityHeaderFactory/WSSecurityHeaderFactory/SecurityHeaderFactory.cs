using System;
using System.Security.Cryptography;
using System.Text;

namespace WSSecurityHeaderFactory
{
    public class SecurityHeaderFactory
    {

        /// <summary>
        /// Convert the values into their designated formats to be used in security header
        /// </summary>
        /// <param name="password">Password known by the user</param>
        /// <param name="nonce">Outs a string with a randomic value used to sign each request with it</param>
        /// <param name="passwordDigest">Converted password in format Base64(SHA1(nonce+created+password))</param>
        /// <param name="created">Timestamp with current date</param>
        /// <param name="expires">Timestamp with expiration date of the request</param>
        /// <param name="nanos">Timeticks from current date</param>
        public void ComputeValues(string password, out string nonce, out string passwordDigest, out string created, out string expires, out string nanos)
        {
            var msNonce = new Microsoft.Web.Services3.Security.Nonce(16);
            nonce = msNonce.Value;

            DateTime dt = DateTime.UtcNow;
            created = dt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            expires = dt.AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            string basedPassword = (password);
            byte[] combined = BuildBytes(nonce, created, basedPassword);
            passwordDigest = System.Convert.ToBase64String(SHAOneHash(combined));

            nanos = dt.Subtract(new DateTime(1970, 1, 1)).Ticks.ToString().Substring(0, 16);
        }

        /// <summary>
        /// Concats nonce, created and password into a single byte array
        /// </summary>
        /// <param name="nonce">String with a randomic value used to sign each request with it</param>
        /// <param name="createdString">Timestamp with current date</param>
        /// <param name="basedPassword">Password known by the user</param>
        /// <returns></returns>
        private static byte[] BuildBytes(string nonce, string createdString, string basedPassword)
        {
            byte[] nonceBytes = System.Convert.FromBase64String(nonce);
            byte[] time = Encoding.UTF8.GetBytes(createdString);
            byte[] pwd = Encoding.UTF8.GetBytes(basedPassword);

            byte[] operand = new byte[nonceBytes.Length + time.Length + pwd.Length];
            Array.Copy(nonceBytes, operand, nonceBytes.Length);
            Array.Copy(time, 0, operand, nonceBytes.Length, time.Length);
            Array.Copy(pwd, 0, operand, nonceBytes.Length + time.Length, pwd.Length);

            return operand;
        }

        /// <summary>
        /// Makes a hash based on SHA1 algorythm 
        /// </summary>
        /// <param name="data">Data to be hashed</param>
        /// <returns>SHA1 hashed input</returns>
        public static byte[] SHAOneHash(byte[] data)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(data);
                return hash;
            }
        }
    }
}
