using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace SecureAPI.Middleware
{
    // ==================================================================================
    // CUSTOM JWT MIDDLEWARE (EDUCATIONAL APPROACH)
    // ==================================================================================
    // This middleware demonstrates how JWT authentication works under the hood.
    // 
    // WHAT IT DOES:
    // 1. Intercepts every HTTP request before it reaches controllers
    // 2. Extracts JWT token from the Authorization header
    // 3. Validates the token manually (signature, expiration, claims)
    // 4. Populates HttpContext.User with claims if token is valid
    // 5. Returns 401 Unauthorized if token is missing or invalid
    // 6. Allows request to proceed if authenticated or endpoint is public
    //
    // WHEN TO USE THIS APPROACH:
    // - Learning how JWT authentication works internally
    // - Need very specific custom validation logic
    // - Educational projects and tutorials
    // - Understanding ASP.NET Core middleware pipeline
    //
    // WHEN NOT TO USE:
    // - Production applications (use standard JWT Bearer authentication instead)
    // - When you need integration with ASP.NET Core Identity
    // - When you want Microsoft-maintained, optimized code
    //
    // See Documentation/JWT_AUTHENTICATION_APPROACHES.md for detailed comparison
    // ==================================================================================

    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<JwtMiddleware> _logger;

        // ===== PUBLIC ENDPOINTS =====
        // These endpoints don't require authentication
        // Anyone can access them without a JWT token
        private readonly string _loginEndpoint = "/api/auth/login";
        private readonly string _publicEndpoint = "/api/test/public";

        // ===== JWT CONFIGURATION =====
        private readonly string _clientSecret;
        private readonly string _issuer;
        private readonly string _audience;

        public JwtMiddleware(
            RequestDelegate next,
            ILogger<JwtMiddleware> logger,
            IOptions<JwtSettings> jwtSettings)
        {
            _next = next;
            _logger = logger;

            // Get JWT settings from dependency injection
            var settings = jwtSettings.Value;
            _clientSecret = settings.ClientSecret;
            _issuer = settings.Issuer;
            _audience = settings.Audience;
        }

        // ==================================================================================
        // MAIN MIDDLEWARE INVOKE METHOD
        // ==================================================================================
        // This method is called for EVERY HTTP request.
        // The ASP.NET Core pipeline executes middleware in the order they're registered.
        //
        // Flow:
        // Request → JwtMiddleware → Other Middleware → Controller → Response
        // ==================================================================================
        public async Task Invoke(HttpContext context)
        {
            var endpoint = context.Request.Path.Value;

            // ===== STEP 1: CHECK IF ENDPOINT REQUIRES AUTHENTICATION =====
            // Some endpoints (like login and public test) don't need tokens
            if (endpoint is not null && IsTokenNotRequired(endpoint))
            {
                _logger.LogInformation("Public endpoint accessed: {Endpoint}", endpoint);
                await _next(context); // Skip authentication, proceed to next middleware
                return;
            }

            // ===== STEP 2: EXTRACT TOKEN FROM AUTHORIZATION HEADER =====
            // Standard format: "Authorization: Bearer <token>"
            // We split by space and take the last part (the actual token)
            var token = context.Request.Headers["Authorization"]
                .FirstOrDefault()? // Get first Authorization header (if exists)
                .Split(" ")        // Split by space: ["Bearer", "<token>"]
                .Last();           // Get the token part

            // ===== STEP 3: HANDLE MISSING TOKEN =====
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Authentication failed: No token provided for {Path}", context.Request.Path);
                
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                
                var error = ApiError.Unauthorized(
                    "Missing authentication token",
                    "Include 'Authorization: Bearer <token>' header in your request");
                
                await context.Response.WriteAsJsonAsync(error);
                return; // Stop here, don't proceed to next middleware
            }

            // ===== STEP 4: VALIDATE THE TOKEN =====
            // This is where the actual JWT validation happens
            var claimPrincipal = ValidateToken(token);

            // ===== STEP 5: HANDLE INVALID TOKEN =====
            if (claimPrincipal is null)
            {
                _logger.LogWarning("Authentication failed: Invalid token for {Path}", context.Request.Path);
                
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                
                var error = ApiError.Unauthorized(
                    "Invalid authentication token",
                    "Token may be expired, malformed, or have an invalid signature");
                
                await context.Response.WriteAsJsonAsync(error);
                return; // Stop here, don't proceed to next middleware
            }

            // ===== STEP 6: ATTACH USER TO HTTPCONTEXT =====
            // If we reach here, the token is valid!
            // Set HttpContext.User so controllers can access user information
            // This enables [Authorize] attributes and User.Identity to work
            context.User = claimPrincipal;

            _logger.LogInformation("User authenticated: {User} accessing {Path}",
                claimPrincipal.Identity?.Name ?? "Unknown",
                context.Request.Path);

            // ===== STEP 7: CONTINUE TO NEXT MIDDLEWARE =====
            // Pass the request to the next middleware in the pipeline
            await _next(context);
        }

        // ==================================================================================
        // CHECK IF ENDPOINT IS PUBLIC (NO AUTHENTICATION REQUIRED)
        // ==================================================================================
        // Returns true if the endpoint doesn't require a JWT token.
        //
        // Common public endpoints:
        // - Login endpoint (users need to login to get a token)
        // - Public API endpoints (health checks, documentation, etc.)
        // - Swagger UI endpoints (in development)
        //
        // In production apps, you might:
        // - Store public endpoints in configuration
        // - Use endpoint metadata/attributes instead of hardcoded paths
        // - Implement more sophisticated route matching
        // ==================================================================================
        private bool IsTokenNotRequired(string endpoint)
        {
            return endpoint.StartsWith(_loginEndpoint, StringComparison.OrdinalIgnoreCase) ||
                   endpoint.StartsWith(_publicEndpoint, StringComparison.OrdinalIgnoreCase);
        }

        // ==================================================================================
        // VALIDATE JWT TOKEN
        // ==================================================================================
        // This method performs the actual JWT validation.
        // 
        // JWT TOKEN STRUCTURE:
        // A JWT has 3 parts separated by dots: HEADER.PAYLOAD.SIGNATURE
        // 
        // 1. HEADER: Algorithm and token type
        //    Example: {"alg": "HS256", "typ": "JWT"}
        //
        // 2. PAYLOAD: Claims (user data)
        //    Example: {"sub": "admin", "role": "Admin", "exp": 1234567890}
        //
        // 3. SIGNATURE: Cryptographic signature to verify authenticity
        //    Created by: HMACSHA256(base64(header) + "." + base64(payload), secret)
        //
        // VALIDATION STEPS:
        // 1. Decode the token (base64 decode header and payload)
        // 2. Verify signature using the secret key (prevents tampering)
        // 3. Check expiration time (exp claim)
        // 4. Validate issuer (iss claim) - who created the token
        // 5. Validate audience (aud claim) - who the token is for
        // 6. Extract claims and create ClaimsPrincipal
        //
        // RETURNS:
        // - ClaimsPrincipal if token is valid (contains user identity and claims)
        // - null if token is invalid (expired, wrong signature, malformed, etc.)
        // ==================================================================================
        private ClaimsPrincipal? ValidateToken(string token)
        {
            try
            {
                // ===== STEP 1: CREATE TOKEN HANDLER =====
                // JwtSecurityTokenHandler is the built-in class for JWT operations
                // It can read, validate, and create JWT tokens
                var tokenHandler = new JwtSecurityTokenHandler();

                // ===== STEP 2: PREPARE SIGNING KEY =====
                // Convert secret string to bytes for cryptographic operations
                // This key is used to verify the token's signature
                // SECURITY: In production, use a strong, random secret (256+ bits)
                var keyBytes = Encoding.UTF8.GetBytes(_clientSecret);

                // ===== STEP 3: CONFIGURE VALIDATION PARAMETERS =====
                // These parameters define what makes a token valid
                var validationParameters = new TokenValidationParameters
                {
                    // ----- ISSUER VALIDATION -----
                    // Issuer = Who created the token (e.g., "SecureAPI")
                    // Prevents tokens from other systems being used
                    ValidateIssuer = true,
                    ValidIssuer = _issuer,

                    // ----- AUDIENCE VALIDATION -----
                    // Audience = Who the token is intended for (e.g., "SecureAPIClients")
                    // Prevents token reuse across different services
                    ValidateAudience = true,
                    ValidAudience = _audience,

                    // ----- LIFETIME VALIDATION -----
                    // Checks if token has expired using the 'exp' claim
                    // Tokens have a limited lifespan for security
                    ValidateLifetime = true,

                    // ----- SIGNATURE VALIDATION -----
                    // CRITICAL: Verifies the token hasn't been tampered with
                    // Uses the secret key to verify HMAC signature
                    // NEVER set this to false in production!
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(keyBytes),

                    // ----- CLOCK SKEW -----
                    // Default is 5 minutes - accepts tokens even if expired up to 5 min ago
                    // This accounts for clock differences between servers
                    // Set to Zero for strict validation (good for learning)
                    ClockSkew = TimeSpan.Zero
                };

                // ===== STEP 4: VALIDATE TOKEN AND EXTRACT CLAIMS =====
                // ValidateToken does all the heavy lifting:
                // - Decodes the JWT
                // - Verifies signature
                // - Checks expiration
                // - Validates issuer and audience
                // - Returns ClaimsPrincipal with user information
                //
                // The 'out _' discards the validated SecurityToken object
                // (we only need the ClaimsPrincipal)
                var claimPrincipal = tokenHandler.ValidateToken(
                    token,
                    validationParameters,
                    out _); // We don't need the validated token object

                // ===== STEP 5: RETURN CLAIMS PRINCIPAL =====
                // ClaimsPrincipal contains:
                // - Identity (who the user is)
                // - Claims (additional user data like roles, permissions)
                //
                // This is what gets assigned to HttpContext.User
                // Controllers can access it via User.Identity.Name, User.IsInRole(), etc.
                _logger.LogInformation("Token validated successfully for user: {User}",
                    claimPrincipal.Identity?.Name ?? "Unknown");

                return claimPrincipal;
            }
            catch (SecurityTokenExpiredException ex)
            {
                // Token has expired (current time > exp claim)
                _logger.LogWarning("Token validation failed: Token expired at {Expiration}",
                    ex.Expires);
                return null;
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                // Token signature is invalid (token was tampered with or wrong secret key)
                _logger.LogWarning("Token validation failed: Invalid signature");
                return null;
            }
            catch (SecurityTokenException ex)
            {
                // Other token validation errors (malformed token, invalid claims, etc.)
                _logger.LogWarning("Token validation failed: {Message}", ex.Message);
                return null;
            }
            catch (Exception ex)
            {
                // Unexpected errors
                _logger.LogError(ex, "Unexpected error during token validation");
                return null;
            }
        }
    }
}
