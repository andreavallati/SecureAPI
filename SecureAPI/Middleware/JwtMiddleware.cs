using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAPI.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<JwtMiddleware> _logger;
        private readonly string _loginEndpoint = "/api/auth/login";
        private readonly string _publicEndpoint = "/api/test/public";
        private readonly string _clientSecret;

        public JwtMiddleware(RequestDelegate next, ILogger<JwtMiddleware> logger, IOptions<JwtSettings> jwtSettings)
        {
            _next = next;
            _logger = logger;
            _clientSecret = jwtSettings.Value.ClientSecret;
        }

        public async Task Invoke(HttpContext context)
        {
            var endpoint = context.Request.Path.Value;

            // Bypass token validation for /api/auth/login and /api/test/public
            if (endpoint is not null && IsTokenNotRequired(endpoint))
            {
                await _next(context);
                return;
            }

            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("No token found.");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Unauthorized: Missing Token");
                return;
            }

            var claimPrincipal = ValidateToken(token);

            if (claimPrincipal is null)
            {
                _logger.LogWarning("Invalid token.");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Unauthorized: Invalid Token");
                return;
            }

            // Attach user to HttpContext
            context.User = claimPrincipal;
            await _next(context);
        }

        private bool IsTokenNotRequired(string endpoint)
        {
            return endpoint.StartsWith(_loginEndpoint, StringComparison.OrdinalIgnoreCase) ||
                   endpoint.StartsWith(_publicEndpoint, StringComparison.OrdinalIgnoreCase);
        }

        private ClaimsPrincipal? ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var keyBytes = Encoding.UTF8.GetBytes(_clientSecret);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(keyBytes)
                };

                var claimPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return claimPrincipal;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Token validation failed: {ex.Message}");
                return null;
            }
        }
    }
}
