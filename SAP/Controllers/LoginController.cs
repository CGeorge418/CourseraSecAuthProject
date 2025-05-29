using Microsoft.AspNetCore.Mvc;

using SecAuthProj.Models;

namespace SecAuthProj.Controllers {
    
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase {

        private readonly SQLWizard _sqlWizard;
        private readonly TokenService _tokenService;

        public LoginController(TokenService tokenService, SQLWizard sqlWizard) {
            _tokenService = tokenService;
            _sqlWizard = sqlWizard;
        }

        [HttpGet]
        public IActionResult GetLoginPage() {
            return PhysicalFile("C:/Users/cgeorge.MECOJAX/Coursera/SecurityAndAuthentication/Project/SAP/webform.html", "text/html");
        }

        [HttpPost]
        public IActionResult Login([FromForm] User request) {
            if (!ValidationHelper.IsValidUsername(request.Username) || !ValidationHelper.IsValidEmail(request.Email) || !ValidationHelper.IsValidPasswrod(request.Password)) {
                return BadRequest("Invalid Input Format");
            }

            var hashed_pass = EncryptionHelper.HashPassword(request.Password);
            if (_sqlWizard.GetUserQuery(request.Username, request.Email, hashed_pass, out string[] user_entry))
            {

                string access_token = _tokenService.GenerateToken(user_entry[0], user_entry[2]);

                Response.Cookies.Append("token", access_token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Strict,
                    Path = "/"
                });                

                return PhysicalFile("C:/Users/cgeorge.MECOJAX/Coursera/SecurityAndAuthentication/Project/SAP/websubmit.html", "text/html");
            }
            else
            {
                return Unauthorized("Invalid Credentials");
            }

        }
    }
}