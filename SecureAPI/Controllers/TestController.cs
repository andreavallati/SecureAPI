using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecureAPI.Controllers
{
    [ApiController]
    [Route("api/test")]
    public class TestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult PublicEndpoint()
        {
            return Ok("This is a public endpoint.");
        }

        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            return Ok("You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminEndpoint()
        {
            return Ok("Hello, Admin!");
        }

        [Authorize(Policy = "AdminPolicy")]
        [HttpGet("admin-policy-secured")]
        public IActionResult AdminPolicySecuredEndpoint()
        {
            return Ok("Secured with Admin Policy");
        }

        [Authorize(Policy = "UserPolicy")]
        [HttpGet("user-policy-secured")]
        public IActionResult UserPolicySecuredEndpoint()
        {
            return Ok("Secured with User Policy");
        }
    }
}
