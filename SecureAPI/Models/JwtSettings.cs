namespace SecureAPI.Models
{
    // ==================================================================================
    // JWT SETTINGS MODEL
    // ==================================================================================
    // This class holds JWT configuration from appsettings.json
    // It's bound to the application using IOptions<JwtSettings> pattern
    //
    // Configuration Binding Example:
    // appsettings.json:
    // {
    //   "JwtSettings": {
    //     "ClientSecret": "your-secret-key",
    //     "UseCustomJwtMiddleware": false,
    //     ...
    //   }
    // }
    //
    // Program.cs:
    // builder.Services.Configure<JwtSettings>(
    //     builder.Configuration.GetSection("JwtSettings"));
    //
    // Then inject IOptions<JwtSettings> wherever you need configuration
    // ==================================================================================

    public class JwtSettings
    {
        // ===== AUTHENTICATION APPROACH SELECTOR =====
        // false = Use standard ASP.NET Core JWT Bearer authentication
        // true = Use custom JWT middleware
        // See Documentation/JWT_AUTHENTICATION_APPROACHES.md for comparison
        public bool UseCustomJwtMiddleware { get; set; } = false;

        // ===== SECRET KEY =====
        // Used to sign and validate JWT tokens
        // SECURITY REQUIREMENTS:
        // - Minimum 256 bits (32 characters) for HS256 algorithm
        // - Use cryptographically random values
        // - Never commit to source control
        // - Store in Azure Key Vault, AWS Secrets Manager, or User Secrets in development
        // - Rotate regularly in production
        public string ClientSecret { get; set; } = string.Empty;

        // ===== ISSUER (iss claim) =====
        // Identifies who created/issued the token
        // Example: "SecureAPI", "https://your-api.com"
        // 
        // Purpose:
        // - Prevents tokens from other systems being accepted
        // - Useful in multi-service architectures
        // 
        // Best Practice: Use your API's domain or unique identifier
        public string Issuer { get; set; } = "SecureAPI";

        // ===== AUDIENCE (aud claim) =====
        // Identifies who the token is intended for (the recipients)
        // Example: "SecureAPIClients", "https://your-app.com"
        //
        // Purpose:
        // - Prevents token reuse across different applications/services
        // - Ensures tokens are only used where intended
        //
        // Best Practice: Use your client application's identifier
        public string Audience { get; set; } = "SecureAPIClients";

        // ===== TOKEN EXPIRATION (exp claim) =====
        // How long tokens remain valid (in minutes)
        // 
        // Recommendations:
        // - Access tokens: 15-60 minutes (shorter = more secure)
        // - Refresh tokens: 7-30 days (use separate refresh token flow)
        // - Admin tokens: 5-15 minutes (higher privileges = shorter lifetime)
        //
        // Security Tradeoff:
        // - Short expiration = More secure but requires more token refreshes
        // - Long expiration = Better UX but higher risk if token is stolen
        //
        // Best Practice: Use short-lived access tokens with refresh tokens
        public int ExpirationMinutes { get; set; } = 60;
    }
}
