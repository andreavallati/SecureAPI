using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAPI.Interfaces;
using SecureAPI.Models;
using System.Security.Claims;

namespace SecureAPI.Controllers
{
    // ==================================================================================
    // AUTHENTICATION CONTROLLER
    // ==================================================================================
    // This controller handles user authentication (login) and profile management.
    //
    // AUTHENTICATION vs AUTHORIZATION:
    // - Authentication = "Who are you?" (proving identity)
    // - Authorization = "What can you do?" (checking permissions)
    //
    // This controller handles AUTHENTICATION (login).
    // Once authenticated, users receive a JWT token to access protected resources.
    // ==================================================================================

    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        public AuthController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        // ==================================================================================
        // LOGIN ENDPOINT (PUBLIC - NO AUTHENTICATION REQUIRED)
        // ==================================================================================
        // POST /api/auth/login
        //
        // This endpoint validates user credentials and returns a JWT token.
        //
        // FLOW:
        // 1. Client sends username and password
        // 2. Server validates credentials (hardcoded here, DB in production)
        // 3. If valid: Generate JWT token with user claims (username, role)
        // 4. Return token to client
        // 5. Client stores token and includes it in future requests
        //
        // SECURITY NOTES:
        // - This is a PUBLIC endpoint (no [Authorize] attribute)
        // - In production: Hash passwords with bcrypt/Argon2, use database
        // - Implement rate limiting to prevent brute force attacks
        // - Log failed login attempts for security monitoring
        // - Consider MFA for sensitive accounts
        //
        // REQUEST BODY:
        // {
        //   "username": "admin",
        //   "password": "admin123"
        // }
        //
        // RESPONSE:
        // {
        //   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        // }
        // ==================================================================================
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // ===== STEP 1: VALIDATE MODEL STATE =====
            // ASP.NET Core automatically validates data annotations
            // If validation fails, ModelState.IsValid will be false
            // This catches issues like missing required fields, invalid lengths, etc.
            if (!ModelState.IsValid)
            {
                // Extract validation errors from ModelState
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return BadRequest(ApiError.BadRequest(
                    "Validation failed",
                    string.Join("; ", errors)));
            }

            // ===== STEP 2: AUTHENTICATE USER =====
            // In production: Query database, verify hashed password
            if (request.Username == "admin" && request.Password == "admin123")
            {
                // Admin user found - generate token with Admin role
                var token = _jwtService.GenerateToken(request.Username, "Admin");
                return Ok(new { token });
            }

            if (request.Username == "user" && request.Password == "user123")
            {
                // Regular user found - generate token with User role
                var token = _jwtService.GenerateToken(request.Username, "User");
                return Ok(new { token });
            }

            // ===== STEP 3: HANDLE INVALID CREDENTIALS =====
            // Return 401 Unauthorized using standardized ApiError format
            // Don't reveal whether username or password was wrong (prevents enumeration attacks)
            return Unauthorized(ApiError.Unauthorized(
                "Authentication failed",
                "Invalid username or password"));
        }

        // ==================================================================================
        // GET USER PROFILE (PROTECTED - AUTHENTICATION REQUIRED)
        // ==================================================================================
        // GET /api/auth/profile
        //
        // This endpoint returns information about the currently authenticated user.
        //
        // FLOW:
        // 1. Client includes JWT token in Authorization header:
        //    Authorization: Bearer <token>
        // 2. Middleware validates token and populates User (HttpContext.User)
        // 3. [Authorize] attribute ensures only authenticated users can access
        // 4. Controller reads user information from User.Identity and User.Claims
        // 5. Return user profile data
        //
        // [Authorize] ATTRIBUTE:
        // - Requires authentication (user must have valid JWT token)
        // - Without token: Returns 401 Unauthorized
        // - With invalid token: Returns 401 Unauthorized
        // - With valid token: Allows access
        //
        // USER OBJECT:
        // - User is ClaimsPrincipal type (from HttpContext)
        // - Contains Identity (who the user is)
        // - Contains Claims (additional user data)
        // - Populated by authentication middleware
        //
        // RESPONSE:
        // {
        //   "username": "admin",
        //   "role": "Admin"
        // }
        // ==================================================================================
        [Authorize] // Requires valid JWT token
        [HttpGet("profile")]
        public IActionResult GetUserProfile()
        {
            // ===== EXTRACT USER INFORMATION FROM CLAIMS =====
            // The User object is populated by authentication middleware
            // It contains claims from the JWT token

            // Get username from ClaimTypes.Name claim
            // This was set in JwtService.GenerateToken()
            var userName = User.Identity?.Name;

            // Get role from ClaimTypes.Role claim
            // Used for role-based authorization
            var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            // Additional claims you might access:
            // var userId = User.FindFirst("user_id")?.Value;
            // var email = User.FindFirst(ClaimTypes.Email)?.Value;
            // var permissions = User.FindAll("permissions").Select(c => c.Value);

            // ===== VALIDATE CLAIMS =====
            // This shouldn't happen if authentication middleware is working correctly
            // But it's good practice to validate data
            if (userName is null || role is null)
            {
                return Unauthorized(ApiError.Unauthorized(
                    "Invalid user data",
                    "User claims are missing or invalid"));
            }

            // ===== BUILD RESPONSE =====
            // In production, you might:
            // - Query database for additional user data
            // - Return user preferences, settings, permissions
            // - Include avatar URL, email, profile info
            var userProfile = new
            {
                Username = userName,
                Role = role,
                // Additional fields:
                // Email = email,
                // IsEmailVerified = true,
                // ProfilePictureUrl = "https://...",
                // Permissions = new[] { "read", "write" }
            };

            return Ok(userProfile);
        }
    }
}
