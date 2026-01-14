using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAPI.Authorization;
using SecureAPI.Interfaces;
using SecureAPI.Middleware;
using SecureAPI.Models;
using SecureAPI.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ==================================================================================
// CONFIGURATION: Bind JWT Settings from appsettings.json
// ==================================================================================
// This allows us to access JWT configuration throughout the application
// via dependency injection using IOptions<JwtSettings>
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

// Get JWT settings to determine which authentication approach to use
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()
    ?? throw new InvalidOperationException("JwtSettings configuration is missing");

// ==================================================================================
// APPROACH SELECTION: Standard vs Custom JWT Authentication
// ==================================================================================
// This project demonstrates TWO authentication approaches:
// 
// 1. STANDARD APPROACH (UseCustomJwtMiddleware = false):
//    - Uses built-in ASP.NET Core JWT Bearer authentication
//    - Industry standard, recommended for production
//    - Less code, more maintainable, Microsoft-supported
//
// 2. CUSTOM APPROACH (UseCustomJwtMiddleware = true):
//    - Uses custom middleware that manually validates JWT tokens
//    - Educational, shows how JWT validation works internally
//    - More control, but more maintenance burden
//
// Toggle between approaches in appsettings.json using "UseCustomJwtMiddleware"
// See Documentation/JWT_AUTHENTICATION_APPROACHES.md for detailed comparison
// ==================================================================================

if (!jwtSettings.UseCustomJwtMiddleware)
{
    // ==================================================================================
    // APPROACH 1: STANDARD ASP.NET CORE JWT BEARER AUTHENTICATION
    // ==================================================================================
    // This is the RECOMMENDED approach for production applications.
    // 
    // What it does:
    // - Automatically extracts JWT tokens from Authorization header
    // - Validates token signature, expiration, issuer, and audience
    // - Populates HttpContext.User with claims from the token
    // - Integrates seamlessly with [Authorize] attributes
    // - Provides extensibility through events (OnTokenValidated, OnAuthenticationFailed, etc.)
    //
    // Benefits:
    // - Battle-tested and optimized by Microsoft
    // - Automatic 401 Unauthorized responses for invalid/missing tokens
    // - Works with ASP.NET Core Identity
    // - Supports multiple authentication schemes
    // ==================================================================================

    builder.Services.AddAuthentication(options =>
    {
        // Set JWT Bearer as the default authentication scheme
        // This means [Authorize] attributes will use JWT authentication by default
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        // Token Validation Parameters: Define what makes a token valid
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // ===== SIGNATURE VALIDATION =====
            // CRITICAL: Always validate the signing key to prevent token forgery
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings.ClientSecret)),

            // ===== ISSUER VALIDATION =====
            // Validates who created the token (prevents tokens from other systems)
            // In production: Set to true and specify your API's issuer
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,

            // ===== AUDIENCE VALIDATION =====
            // Validates who the token is intended for (prevents token reuse across services)
            // In production: Set to true and specify your API's audience
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,

            // ===== LIFETIME VALIDATION =====
            // Ensures token hasn't expired
            ValidateLifetime = true,

            // ===== CLOCK SKEW =====
            // Default is 5 minutes - tokens are accepted even if expired up to 5 minutes ago
            // Set to Zero for strict expiration (recommended for learning/testing)
            ClockSkew = TimeSpan.Zero
        };

        // ===== AUTHENTICATION EVENTS =====
        // Optional: Handle authentication events for logging, custom logic, etc.
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                // Log authentication failures for security monitoring
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogWarning("JWT Authentication failed: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // Optional: Add custom claims or validation logic here
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogInformation("JWT Token validated for user: {User}",
                    context.Principal?.Identity?.Name ?? "Unknown");
                return Task.CompletedTask;
            }
        };
    });
}
else
{
    // ==================================================================================
    // APPROACH 2: CUSTOM JWT MIDDLEWARE (EDUCATIONAL)
    // ==================================================================================
    // This approach uses custom middleware to manually validate JWT tokens.
    // 
    // What it does:
    // - Custom middleware intercepts requests before they reach controllers
    // - Manually extracts and validates JWT tokens using JwtSecurityTokenHandler
    // - Manually populates HttpContext.User with claims
    // - Provides full control over the authentication process
    //
    // When to use:
    // - Learning how JWT authentication works under the hood
    // - Need very specific custom validation logic not supported by standard approach
    // - Educational demonstrations and tutorials
    //
    // Note: This approach still uses AddAuthentication() to enable authorization,
    // but the actual authentication (token validation) is done by custom middleware
    // ==================================================================================

    // We still need to add authentication services for authorization to work
    // But we won't configure JWT Bearer since our custom middleware handles validation
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme);
}

// ==================================================================================
// AUTHORIZATION CONFIGURATION
// ==================================================================================
// Authorization determines what authenticated users can do.
// This configuration works with BOTH authentication approaches.

builder.Services.AddAuthorization(options =>
{
    // ===== CUSTOM AUTHORIZATION POLICIES =====
    // Policies provide flexible, reusable authorization rules
    // 
    // Example: AdminPolicy checks if user has "Admin" role
    // Usage: [Authorize(Policy = "AdminPolicy")]
    options.AddPolicy("AdminPolicy", policy =>
        policy.Requirements.Add(new RoleRequirement("Admin")));

    options.AddPolicy("UserPolicy", policy =>
        policy.Requirements.Add(new RoleRequirement("User")));

    // Note: You can also use built-in role authorization without custom policies:
    // [Authorize(Roles = "Admin")] - This is simpler and works out of the box
    // Custom policies are useful when you need complex authorization logic
});

// Register custom authorization handler for RoleRequirement
// This handler is invoked when a policy uses RoleRequirement
builder.Services.AddSingleton<IAuthorizationHandler, RoleAuthorizationHandler>();

// ==================================================================================
// JWT SERVICE REGISTRATION
// ==================================================================================
// IJwtService is responsible for generating JWT tokens (used in AuthController)
builder.Services.AddSingleton<IJwtService>(sp =>
{
    var settings = sp.GetRequiredService<IOptions<JwtSettings>>().Value;
    return new JwtService(settings.ClientSecret, settings.Issuer, settings.Audience, settings.ExpirationMinutes);
});

// ==================================================================================
// ASP.NET CORE SERVICES
// ==================================================================================
builder.Services.AddControllers();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "Secure API", Version = "v1" });

    // Add JWT Authentication to Swagger UI
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer {token}'",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ==================================================================================
// APPLICATION PIPELINE CONFIGURATION
// ==================================================================================
var app = builder.Build();

// Swagger UI for API testing (Development only)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ==================================================================================
// MIDDLEWARE PIPELINE ORDER IS CRITICAL!
// ==================================================================================
// The order of middleware matters in ASP.NET Core.
// Request processing flows top to bottom, response flows bottom to top.
//
// Typical order:
// 1. Exception handling
// 2. HTTPS redirection
// 3. Routing
// 4. CORS
// 5. Authentication (who are you?)
// 6. Authorization (what can you do?)
// 7. Endpoints (controllers)
// ==================================================================================

if (jwtSettings.UseCustomJwtMiddleware)
{
    // ===== CUSTOM JWT MIDDLEWARE =====
    // When using custom approach, this middleware:
    // - Extracts JWT token from Authorization header
    // - Validates token manually using JwtSecurityTokenHandler
    // - Sets HttpContext.User if token is valid
    // - Returns 401 Unauthorized for invalid tokens
    //
    // IMPORTANT: Custom middleware must run BEFORE UseAuthorization()
    // because authorization needs HttpContext.User to be populated
    app.UseMiddleware<JwtMiddleware>();

    app.UseAuthorization();

    app.MapGet("/", () => "SecureAPI is running with CUSTOM JWT Middleware! " +
        "See Documentation/JWT_AUTHENTICATION_APPROACHES.md to learn more.");
}
else
{
    // ===== STANDARD JWT BEARER AUTHENTICATION =====
    // When using standard approach:
    // - UseAuthentication() activates the JWT Bearer middleware
    // - It automatically validates tokens and populates HttpContext.User
    // - UseAuthorization() then checks if user has required permissions
    //
    // IMPORTANT: UseAuthentication() must run BEFORE UseAuthorization()
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapGet("/", () => "SecureAPI is running with STANDARD JWT Bearer Authentication! " +
        "See Documentation/JWT_AUTHENTICATION_APPROACHES.md to learn more.");
}

app.MapControllers();

// ==================================================================================
// LOG STARTUP INFORMATION
// ==================================================================================
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("==========================================================");
logger.LogInformation("SecureAPI Started");
logger.LogInformation("Authentication Approach: {Approach}",
    jwtSettings.UseCustomJwtMiddleware ? "CUSTOM MIDDLEWARE" : "STANDARD JWT BEARER");
logger.LogInformation("Documentation: See Documentation/JWT_AUTHENTICATION_APPROACHES.md");
logger.LogInformation("==========================================================");

await app.RunAsync();