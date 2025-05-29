using System.Security.Cryptography;
using System.Text;

namespace SecAuthProj {
    public class EncryptionHelper {

        private static readonly SHA256 _sha = SHA256.Create();

        public static string HashPassword(string password) {
            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
            }

            byte[] bytes = _sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }
    }
}