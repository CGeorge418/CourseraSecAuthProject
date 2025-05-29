using System.Net;
using NUnit.Framework;

namespace SAPTests
{
    [TestFixture]
    public class TestInputValidation {

        private static readonly HttpClient _client = new();

        [Test]
        public void TestForSQLInjection() {
            Console.WriteLine("Test 1; Expected: 400");
            Assert.That(
                InputTestFunction(
                    "user2'; DROP TABLE Users; --",
                    "email2@email.com",
                    "password2") 
                is HttpStatusCode.BadRequest, 
                "SQL Injection should not be allowed."
            );

            Console.WriteLine("Test 2; Expected: 400");
            Assert.That(
                InputTestFunction(
                    "user2", 
                    "email2@email.com'; DROP TABLE Users; --",
                    "password2")
                is HttpStatusCode.BadRequest, 
                "SQL Injection should not be allowed."
            );

            Console.WriteLine("Test 3; Expected: 401");
            Assert.That(
                InputTestFunction(
                    "' OR '1'='1", 
                    "email2@email.com",
                    "password2")
                is HttpStatusCode.Unauthorized, 
                "SQL Injection should not be allowed."
            );
            
            Console.WriteLine("Test 4; Expected: 400");
            Assert.That(
                InputTestFunction(
                    "user2",
                    "' OR '1'='1",
                    "password2")
                is HttpStatusCode.BadRequest, 
                "SQL Injection should not be allowed."
            );

            Console.WriteLine("Test 5; Expected: 200");
            Assert.That(
                InputTestFunction(
                    "user2",
                    "email2@email.com",
                    "password2")
                is HttpStatusCode.OK, 
                "Do not reject Valid Input."
            );
        }

        [Test]
        public void TestForXSS() {
            Console.WriteLine("Test 1; Expected: 400");
            Assert.That(
                InputTestFunction(
                    "<script>alert('XSS');</script>",
                    "email3@email.com",
                    "password3") 
                is HttpStatusCode.BadRequest, 
                "SQL Injection should not be allowed."
            );

            Console.WriteLine("Test 2; Expected: 400");
            Assert.That(
                InputTestFunction(
                    "user3", 
                    "<script>alert('email3@email.com');</script>",
                    "password3")
                is HttpStatusCode.BadRequest, 
                "SQL Injection should not be allowed."
            );

            Console.WriteLine("Test 3; Expected: 200");
            Assert.That(
                InputTestFunction(
                    "user3", 
                    "email3@email.com",
                    "password3") 
                is HttpStatusCode.OK, 
                "SQL Injection should not be allowed."
            );
        }

        public static HttpStatusCode InputTestFunction(string username, string email, string password) {

            // var content = new StringContent(@"
            // {
            //     ""Username"": """ + username + @""",
            //     ""Email"": """ + email + @""",
            //     ""Password"": """ + password + @"""
            // }", 
            // System.Text.Encoding.UTF8, 
            // "application/json");

            var content = new Dictionary<string, string>() {
                {"username", username},
                {"email", email},
                {"password", password}
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:5231/login") {
                Content = new FormUrlEncodedContent(content)
            };
            var response = _client.SendAsync(request);
            return response.Result.StatusCode;
        }
        
    }

    [TestFixture]
    public class TestAuthNZ {

        [Test]
        public void TestAuthN() {

            // Valid Login
            Assert.That(
                GetAuthNStatus(
                    "user3",
                    "email3@email.com",
                    "password3")
                is HttpStatusCode.OK,
                "Valid login should return Ok with token.");

            // Invalid Login - Wrong Creds
            Assert.That(
                GetAuthNStatus(
                    "user1",
                    "email2@email.com",
                    "password3")
                is HttpStatusCode.Unauthorized,
                "Invalid login should return Unauthorized.");

            // Invalid Login - Invalid Input
            Assert.That(
                GetAuthNStatus(
                    "%$@^@%^!*&^$#",
                    "email1@email.com",
                    "password1")
                is HttpStatusCode.BadRequest,
                "Invalid input should return BadRequest.");

             // Invalid Login - Invalid Input
            Assert.That(
                GetAuthNStatus(
                    "user1",
                    "email1 email.com",
                    "password1")
                 is HttpStatusCode.BadRequest,
                 "Invalid input should return BadRequest.");
        }

        public static HttpStatusCode GetAuthNStatus(string username, string email, string password) {
            // var content = new StringContent(@"
            // {
            //     ""Username"": """ + username + @""",
            //     ""Email"": """ + email + @""",
            //     ""Password"": """ + password + @"""
            // }", 
            // System.Text.Encoding.UTF8, 
            // "application/json");

            var _client = new HttpClient();

            var content = new Dictionary<string, string>() {
                {"username", username},
                {"email", email},
                {"password", password}
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:5231/login") {
                Content = new FormUrlEncodedContent(content)
            };
            var response = _client.SendAsync(request);
            return response.Result.StatusCode;
        }

        [Test]
        public void TestAuthZ() {

            Assert.That(
                GetAuthZStatus(
                    "user1",
                    "email1@email.com",
                    "password1")
                is HttpStatusCode.OK, 
                "Admins can access admin endpoint.");
            
            Assert.That(
                GetAuthZStatus(
                    "user3",
                    "email3@email.com",
                    "password3")
                is HttpStatusCode.Forbidden,
                "Users cannot access admin endpoint.");
            
        }

        public static HttpStatusCode GetAuthZStatus(string username, string email, string password) {

            var cookieContainer = new CookieContainer();
            var uri = new Uri("http://localhost:5231/login");
            var httpClientHandler = new HttpClientHandler() {
                CookieContainer = cookieContainer
            };
            var _client = new HttpClient(httpClientHandler);

            var content = new Dictionary<string, string>() {
                {"username", username},
                {"email", email},
                {"password", password}
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:5231/login") {
                Content = new FormUrlEncodedContent(content)
            };
            var response = _client.SendAsync(request).Result;

            if (response.IsSuccessStatusCode) {

                var token = cookieContainer.GetCookies(uri)["token"]?.Value;

                _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                return _client.GetAsync("http://localhost:5231/admin").Result.StatusCode;
            }
            return response.StatusCode;
        }
    }
}