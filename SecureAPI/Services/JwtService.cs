using Microsoft.IdentityModel.Tokens;
using SecureAPI.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAPI.Services
{
    // ==================================================================================
    // JWT SERVICE - TOKEN GENERATION
    // ==================================================================================
    // This service is responsible for creating JWT tokens when users successfully login.
    // 
    // WHAT IT DOES:
    // 1. Takes user information (username, role)
    // 2. Creates claims (key-value pairs about the user)
    // 3. Signs the token with a secret key
    // 4. Returns a JWT string that clients can use for authentication
    //
    // JWT TOKEN STRUCTURE:
    // A JWT consists of 3 parts separated by dots: HEADER.PAYLOAD.SIGNATURE
    //
    // Example: eyJhbGc...payload...signature
    //
    // 1. HEADER (base64 encoded JSON):
    //    {"alg": "HS256", "typ": "JWT"}
    //    - alg: Signing algorithm (HMAC SHA256)
    //    - typ: Token type (JWT)
    //
    // 2. PAYLOAD (base64 encoded JSON):
    //    {"sub": "admin", "role": "Admin", "exp": 1234567890}
    //    - Contains claims (user data)
    //    - Not encrypted, just encoded (anyone can read it!)
    //    - Never put sensitive data (passwords, SSN, etc.) in tokens
    //
    // 3. SIGNATURE:
    //    HMACSHA256(base64(header) + "." + base64(payload), secret)
    //    - Proves the token hasn't been tampered with
    //    - Can only be created by someone with the secret key
    //    - If payload changes, signature won't match
    //
    // IMPORTANT: JWTs are signed, not encrypted. Anyone can decode and read them.
    // The signature only proves authenticity, it doesn't hide data.
    // ==================================================================================

    public class JwtService : IJwtService
    {
        private readonly string _key;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _expirationMinutes;

        // ===== CONSTRUCTOR =====
        // Receives JWT configuration from dependency injection
        // These values come from appsettings.json via IOptions<JwtSettings>
        public JwtService(string key, string issuer, string audience, int expirationMinutes)
        {
            _key = key;
            _issuer = issuer;
            _audience = audience;
            _expirationMinutes = expirationMinutes;
        }

        // ==================================================================================
        // GENERATE JWT TOKEN
        // ==================================================================================
        // Creates a signed JWT token for an authenticated user.
        //
        // PARAMETERS:
        // - username: User's identifier (stored in 'sub' or ClaimTypes.Name claim)
        // - role: User's role for authorization (stored in ClaimTypes.Role claim)
        //
        // RETURNS:
        // - A JWT string that can be sent to the client
        //
        // USAGE FLOW:
        // 1. User logs in with valid credentials
        // 2. AuthController calls this method to generate token
        // 3. Token is returned to client
        // 4. Client includes token in Authorization header for subsequent requests
        // 5. Middleware validates token and grants access
        // ==================================================================================
        public string GenerateToken(string username, string role)
        {
            // ===== STEP 1: CREATE CLAIMS =====
            // Claims are statements about the user (key-value pairs)
            // They become part of the JWT payload
            //
            // Standard Claims (registered in JWT spec):
            // - sub (subject): User identifier
            // - iat (issued at): When token was created
            // - exp (expiration): When token expires
            // - iss (issuer): Who created the token
            // - aud (audience): Who the token is for
            //
            // Custom Claims:
            // - role: For authorization (Admin, User, etc.)
            // - email, permissions, etc. (add as needed)
            var claims = new[]
            {
                // This is the standard claim for user identity
                // Accessible via User.Identity.Name in controllers
                new Claim(ClaimTypes.Name, username),

                // Standard claim for role-based authorization
                // Enables [Authorize(Roles = "Admin")] to work
                // Accessible via User.IsInRole("Admin") in controllers
                new Claim(ClaimTypes.Role, role)

                // Additional claims you might add:
                // new Claim(ClaimTypes.Email, email),
                // new Claim("user_id", userId),
                // new Claim("permissions", "read,write"),
                // new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique token ID
            };

            // ===== STEP 2: PREPARE SIGNING KEY =====
            // Convert secret string to bytes for cryptographic operations
            // This key is used to create the HMAC signature
            //
            // HMAC (Hash-based Message Authentication Code):
            // - Combines hashing (SHA256) with a secret key
            // - Creates a signature that proves token authenticity
            // - Only someone with the secret can create valid signatures
            //
            // KEY REQUIREMENTS:
            // - Minimum 256 bits (32 characters) for HS256
            // - Use cryptographically strong random values
            // - Keep secret, never expose to clients
            // - Store securely (Key Vault, environment variables)
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));

            // ===== STEP 3: CREATE SIGNING CREDENTIALS =====
            // Specifies how to sign the token
            // - Key: The secret key
            // - Algorithm: HMAC SHA256 (HS256)
            //
            // ALGORITHM OPTIONS:
            // - HS256: HMAC with SHA-256 (symmetric, same key for sign and verify)
            // - RS256: RSA with SHA-256 (asymmetric, public/private key pair)
            // - ES256: ECDSA with SHA-256 (asymmetric, elliptic curve)
            //
            // HS256 is simplest but both parties need the secret.
            // RS256 is better for microservices (public key can be shared).
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // ===== STEP 4: CREATE JWT SECURITY TOKEN =====
            // This creates the actual token object with all components
            var token = new JwtSecurityToken(
                // ===== ISSUER (iss claim) =====
                // Who created/issued this token
                // Helps prevent tokens from other systems being accepted
                issuer: _issuer,

                // ===== AUDIENCE (aud claim) =====
                // Who this token is intended for
                // Prevents token reuse across different applications
                audience: _audience,

                // ===== CLAIMS (PAYLOAD) =====
                // User information and metadata
                claims: claims,

                // ===== NOT BEFORE (nbf claim) =====
                // Token is not valid before this time
                // Usually set to current time (token valid immediately)
                // Can be set to future time for scheduled activation
                notBefore: DateTime.UtcNow,

                // ===== EXPIRATION (exp claim) =====
                // Token is not valid after this time
                // SECURITY: Short expiration = more secure (harder to abuse stolen tokens)
                // USABILITY: Long expiration = better UX (less frequent re-authentication)
                //
                // BEST PRACTICES:
                // - Access tokens: 15-60 minutes
                // - Refresh tokens: 7-30 days (separate token type)
                // - High-privilege tokens: 5-15 minutes
                //
                // Always use UTC time to avoid timezone issues
                expires: DateTime.UtcNow.AddMinutes(_expirationMinutes),

                // ===== SIGNING CREDENTIALS =====
                // How the token is signed (algorithm and key)
                signingCredentials: credentials
            );

            // ===== STEP 5: SERIALIZE TOKEN TO STRING =====
            // JwtSecurityTokenHandler converts the token object to a JWT string
            // This string is what gets sent to the client
            //
            // The result looks like:
            // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBZG1pbiIsImV4cCI6MTYxMjM0NTY3OH0.signature
            //
            // You can decode this at jwt.io to see the claims (it's just base64, not encrypted!)
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenString;
        }

        // ==================================================================================
        // TOKEN LIFECYCLE
        // ==================================================================================
        //
        // 1. GENERATION (this service):
        //    User logs in → Generate token → Return to client
        //
        // 2. STORAGE (client-side):
        //    - Mobile apps: Secure storage / Keychain
        //    - Web apps: Memory / HttpOnly cookies (not localStorage - XSS risk!)
        //    - Desktop apps: Encrypted credential store
        //
        // 3. USAGE:
        //    Client includes token in every request:
        //    Authorization: Bearer <token>
        //
        // 4. VALIDATION (middleware):
        //    Middleware validates token on each request:
        //    - Verify signature (proves authenticity)
        //    - Check expiration (proves freshness)
        //    - Validate issuer/audience (proves intended use)
        //    - Extract claims (identify user)
        //
        // 5. EXPIRATION:
        //    Token expires → Client gets 401 Unauthorized → Client refreshes token or re-authenticates
        //
        // 6. REVOCATION (optional):
        //    For logout or security concerns:
        //    - Maintain token blacklist (Redis, database)
        //    - Check blacklist during validation
        //    - Or use short expiration + refresh tokens
        //
        // ==================================================================================
    }
}
