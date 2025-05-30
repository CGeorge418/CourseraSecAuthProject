using System.Text;

namespace SecAuthProj
{
    public class ValidationHelper
    {
        private static readonly HashSet<char> ValidUsernameChars = ['_', '.', '-', '/', '\\', '"', '\'', ' ', '='];
        private static readonly HashSet<char> ValidPasswordChars = ['!', '@', '#', '$', '%', '^', '&', '*', '+', '_'];

        public static bool IsValidUsername(string username) {
            // Check if the username is not null or empty
            if (string.IsNullOrEmpty(username)) {
                return false;
            }

            username = DecodeInput(username);

            if (XSSCheck(username)) {
                return false; // Reject if XSS patterns are found
            }

            // Check if the username contains only alphanumeric characters and underscores
            foreach (char c in username) {
                if (!char.IsLetterOrDigit(c) && !ValidUsernameChars.Contains(c)) {
                    return false;
                }
            }

            // Check length constraints
            return username.Length >= 3 && username.Length <= 20;
        }

        public static bool IsValidEmail(string email) {
            // Check if the email is not null or empty
            if (string.IsNullOrEmpty(email)) {
                return false;
            }

            email = DecodeInput(email);

            if (XSSCheck(email)) {
                return false; // Reject if XSS patterns are found
            }

            // Use a simple regex to validate the email format
            var emailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            return System.Text.RegularExpressions.Regex.IsMatch(email, emailPattern);
        }

        public static bool IsValidPasswrod(string password) {
            // Check if the password is not null or empty
            if (string.IsNullOrEmpty(password)) {
                return false;
            }

            password = DecodeInput(password);

            if (XSSCheck(password)) {
                return false; // Reject if XSS patterns are found
            }

            foreach (char c in password) {
                // Check if the password contains only valid characters
                if (!char.IsLetterOrDigit(c) && !ValidPasswordChars.Contains(c)) {
                    return false;
                }
            }

            // Check length constraints
            return password.Length >= 8 && password.Length <= 50;
        }

        public static bool XSSCheck(string input) {

            // Simple XSS check: look for common XSS patterns
            string[] xssPatterns = { "<script", "<iframe", "<object", "<embed", "<form", "<input", "<img", "javascript:", "onerror=", "onload=", "alert(", "confirm(", "prompt(" };
            foreach (var pattern in xssPatterns) {
                if (input.Contains(pattern, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }
            }

            return false;
        }

        public static string DecodeInput(string input) {

            string decoded_input = System.Net.WebUtility.HtmlDecode(input);
            decoded_input = Uri.UnescapeDataString(decoded_input);
            decoded_input = decoded_input.Normalize(NormalizationForm.FormC);
            decoded_input = decoded_input.Trim();

            return decoded_input;
        }
    }
}