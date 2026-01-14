using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SecureAPI.Controllers
{
    // ==================================================================================
    // TEST CONTROLLER - AUTHORIZATION DEMONSTRATIONS
    // ==================================================================================
    // This controller demonstrates different authorization patterns in ASP.NET Core.
    //
    // AUTHORIZATION LEVELS:
    // 1. No authorization - Public access
    // 2. [Authorize] - Any authenticated user
    // 3. [Authorize(Roles = "...")] - Role-based authorization
    // 4. [Authorize(Policy = "...")] - Custom policy authorization
    //
    // Use this controller to test authentication and authorization behavior.
    // ==================================================================================

    [ApiController]
    [Route("api/test")]
    public class TestController : ControllerBase
    {
        // ==================================================================================
        // PUBLIC ENDPOINT (NO AUTHENTICATION REQUIRED)
        // ==================================================================================
        // GET /api/test/public
        //
        // AUTHORIZATION: None (anyone can access)
        // 
        // This endpoint has NO [Authorize] attribute, so:
        // - No JWT token required
        // - Anyone can access (authenticated or not)
        // - Middleware bypasses authentication for this endpoint
        //
        // USE CASES:
        // - Health checks
        // - API documentation
        // - Public content
        // - Login/registration endpoints
        //
        // TEST:
        // curl http://localhost:5000/api/test/public
        // (No Authorization header needed)
        // ==================================================================================
        [HttpGet("public")]
        public IActionResult PublicEndpoint()
        {
            return Ok(new
            {
                message = "This is a public endpoint.",
                authenticated = User.Identity?.IsAuthenticated ?? false,
                info = "No JWT token required. Anyone can access this endpoint."
            });
        }

        // ==================================================================================
        // PROTECTED ENDPOINT (AUTHENTICATION REQUIRED)
        // ==================================================================================
        // GET /api/test/protected
        //
        // AUTHORIZATION: [Authorize] - Any authenticated user
        //
        // The [Authorize] attribute requires:
        // - Valid JWT token in Authorization header
        // - Token must not be expired
        // - Token signature must be valid
        //
        // Without valid token:
        // - Returns 401 Unauthorized
        //
        // With valid token:
        // - Grants access regardless of role
        // - User information available via User object
        //
        // TEST:
        // 1. Login to get token:
        //    curl -X POST http://localhost:5000/api/auth/login \
        //      -H "Content-Type: application/json" \
        //      -d '{"username":"user","password":"user123"}'
        //
        // 2. Use token:
        //    curl http://localhost:5000/api/test/protected \
        //      -H "Authorization: Bearer <your-token>"
        // ==================================================================================
        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            // User is guaranteed to be authenticated here
            // The [Authorize] attribute ensures this
            var username = User.Identity?.Name ?? "Unknown";
            var role = User.FindFirst(ClaimTypes.Role)?.Value ?? "No role";

            return Ok(new
            {
                message = "You are authenticated!",
                username = username,
                role = role,
                info = "This endpoint requires a valid JWT token but accepts any role."
            });
        }

        // ==================================================================================
        // ADMIN ENDPOINT (ROLE-BASED AUTHORIZATION)
        // ==================================================================================
        // GET /api/test/admin
        //
        // AUTHORIZATION: [Authorize(Roles = "Admin")] - Built-in role authorization
        //
        // This endpoint requires:
        // 1. Valid JWT token (authenticated)
        // 2. User must have "Admin" role claim
        //
        // How it works:
        // - Checks if User.IsInRole("Admin") returns true
        // - Role comes from ClaimTypes.Role claim in JWT token
        // - Set during token generation in JwtService
        //
        // Without Admin role:
        // - Returns 403 Forbidden (authenticated but not authorized)
        //
        // With Admin role:
        // - Grants access
        //
        // MULTIPLE ROLES:
        // [Authorize(Roles = "Admin,SuperAdmin")] - Either role works (OR logic)
        //
        // TEST:
        // 1. Login as admin:
        //    curl -X POST http://localhost:5000/api/auth/login \
        //      -H "Content-Type: application/json" \
        //      -d '{"username":"admin","password":"admin123"}'
        //
        // 2. Use admin token:
        //    curl http://localhost:5000/api/test/admin \
        //      -H "Authorization: Bearer <admin-token>"
        //
        // 3. Try with user token (will get 403):
        //    curl http://localhost:5000/api/test/admin \
        //      -H "Authorization: Bearer <user-token>"
        // ==================================================================================
        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminEndpoint()
        {
            var username = User.Identity?.Name ?? "Unknown";

            return Ok(new
            {
                message = $"Hello, {username}!",
                role = "Admin",
                info = "This endpoint uses built-in role-based authorization: [Authorize(Roles = \"Admin\")]"
            });
        }

        // ==================================================================================
        // ADMIN POLICY ENDPOINT (CUSTOM POLICY AUTHORIZATION)
        // ==================================================================================
        // GET /api/test/admin-policy-secured
        //
        // AUTHORIZATION: [Authorize(Policy = "AdminPolicy")] - Custom policy
        //
        // This demonstrates custom authorization policies.
        //
        // How it works:
        // 1. Policy defined in Program.cs:
        //    options.AddPolicy("AdminPolicy", policy =>
        //        policy.Requirements.Add(new RoleRequirement("Admin")));
        //
        // 2. Custom handler (RoleAuthorizationHandler) evaluates requirement
        // 3. Handler checks if user has required role
        //
        // WHEN TO USE POLICIES:
        // - Complex authorization logic (not just roles)
        // - Multiple requirements (e.g., role AND permission AND condition)
        // - Resource-based authorization
        // - Claims-based authorization
        // - Time-based or location-based rules
        //
        // Example complex policy:
        // policy.RequireRole("Admin")
        //       .RequireClaim("department", "IT")
        //       .RequireAssertion(context =>
        //           context.User.HasClaim(c => c.Type == "level" && int.Parse(c.Value) >= 5));
        //
        // NOTE: In this simple case, [Authorize(Roles = "Admin")] would be simpler.
        // Policies are useful for more complex scenarios.
        //
        // TEST: Same as admin endpoint above
        // ==================================================================================
        [Authorize(Policy = "AdminPolicy")]
        [HttpGet("admin-policy-secured")]
        public IActionResult AdminPolicySecuredEndpoint()
        {
            var username = User.Identity?.Name ?? "Unknown";

            return Ok(new
            {
                message = $"Welcome, {username}!",
                securedWith = "Custom AdminPolicy",
                info = "This endpoint uses custom policy authorization. " +
                       "The policy is evaluated by RoleAuthorizationHandler which checks for Admin role. " +
                       "This approach is more flexible for complex authorization rules."
            });
        }

        // ==================================================================================
        // USER POLICY ENDPOINT (CUSTOM POLICY FOR USER ROLE)
        // ==================================================================================
        // GET /api/test/user-policy-secured
        //
        // AUTHORIZATION: [Authorize(Policy = "UserPolicy")] - Custom policy for User role
        //
        // Similar to AdminPolicy but checks for "User" role.
        // Both "admin" and "user" test accounts can access this (admin also has user privileges).
        //
        // TEST:
        // Works with either admin or user token:
        // curl http://localhost:5000/api/test/user-policy-secured \
        //   -H "Authorization: Bearer <token>"
        // ==================================================================================
        [Authorize(Policy = "UserPolicy")]
        [HttpGet("user-policy-secured")]
        public IActionResult UserPolicySecuredEndpoint()
        {
            var username = User.Identity?.Name ?? "Unknown";
            var role = User.FindFirst(ClaimTypes.Role)?.Value ?? "Unknown";

            return Ok(new
            {
                message = $"Welcome, {username}!",
                role = role,
                securedWith = "Custom UserPolicy",
                info = "This endpoint uses custom policy authorization for User role."
            });
        }
    }
}
