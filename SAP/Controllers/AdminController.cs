using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecAuthProj {
    [ApiController]
    [Route("[controller]")]
    public class AdminController : ControllerBase {
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAdminHome() {
            return Ok(new { Message = "Super Secret Admin Data" });
        }
    }
}