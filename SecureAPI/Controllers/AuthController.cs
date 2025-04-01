using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAPI.Interfaces;
using SecureAPI.Models;
using System.Security.Claims;

namespace SecureAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        public AuthController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // In a real-world app, validate credentials from DB
            if (request.Username == "admin" && request.Password == "admin123")
            {
                var token = _jwtService.GenerateToken(request.Username, "Admin");
                return Ok(new { token });
            }
            if (request.Username == "user" && request.Password == "user123")
            {
                var token = _jwtService.GenerateToken(request.Username, "User");
                return Ok(new { token });
            }

            return Unauthorized();
        }

        [Authorize]
        [HttpGet("profile")]
        public IActionResult GetUserProfile()
        {
            var userName = User.Identity?.Name; // Get the username from claims
            var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            if (userName is null || role is null)
            {
                return Unauthorized("Invalid user data.");
            }

            var userProfile = new
            {
                Username = userName,
                Role = role
            };

            return Ok(userProfile);
        }
    }
}
