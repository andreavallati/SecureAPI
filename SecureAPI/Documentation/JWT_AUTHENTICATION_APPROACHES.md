# JWT Authentication Approaches in ASP.NET Core

This project demonstrates **TWO different approaches** to implementing JWT authentication in ASP.NET Core 8. Both are valid, but serve different purposes and learning objectives.

---

## Approach Comparison

| Feature | Standard JWT Bearer | Custom Middleware |
|---------|-------------------|-------------------|
| **Setup Complexity** | Simple | Complex |
| **Code Volume** | Minimal | Significant |
| **Flexibility** | Medium | High |
| **Maintenance** | Low (Microsoft maintains) | High (you maintain) |
| **Performance** | Optimized | Depends on implementation |
| **Learning Value** | Practical usage | Deep understanding |
| **Production Use** | Recommended | Only if needed |
| **Integration** | Seamless with ASP.NET Core | Manual integration |
| **Testing** | Standard test patterns | Custom test setup |

---

## Approach 1: Standard ASP.NET Core JWT Bearer Authentication

### What It Is
Uses the built-in `Microsoft.AspNetCore.Authentication.JwtBearer` package that ASP.NET Core provides out-of-the-box.

### How It Works
1. Configure authentication in `Program.cs` using `AddAuthentication()` and `AddJwtBearer()`
2. ASP.NET Core middleware pipeline automatically validates JWT tokens
3. Claims are populated into `HttpContext.User`
4. Use `[Authorize]` attributes on controllers/actions
5. Built-in role and policy-based authorization works automatically

### Advantages
- **Industry Standard**: What 95% of production apps use
- **Battle-Tested**: Microsoft maintains and optimizes it
- **Less Code**: Configuration over implementation
- **Automatic Features**: 
  - Token validation
  - Claims extraction
  - Error handling (401/403 responses)
  - Integration with ASP.NET Core Identity
  - Support for multiple authentication schemes
- **Better Debugging**: Integrated with ASP.NET Core logging and diagnostics
- **Extensibility**: Event handlers for customization

### Disadvantages
- **Less Control**: Abstraction hides internal logic
- **Learning Gap**: Doesn't teach JWT internals
- **Configuration Complexity**: Many options can be overwhelming
- **Black Box**: Harder to debug if you don't understand what's happening

### Code Example
```csharp
// Program.cs - Standard Approach
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings.ClientSecret)),
            ValidateIssuer = true,
            ValidIssuer = "SecureAPI",
            ValidateAudience = true,
            ValidAudience = "SecureAPIClients",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

app.UseAuthentication(); // Automatically validates tokens
app.UseAuthorization();
```

---

## Approach 2: Custom JWT Middleware

### What It Is
A custom-built middleware component that manually validates JWT tokens before they reach controllers.

### How It Works
1. Custom `JwtMiddleware` intercepts every HTTP request
2. Manually extract token from `Authorization` header
3. Use `JwtSecurityTokenHandler` to validate token
4. Manually populate `HttpContext.User` with claims
5. Handle errors and return appropriate status codes
6. Call `next()` to continue pipeline

### Advantages
- **Full Control**: You control every aspect of validation
- **Educational**: Learn JWT internals and token validation
- **Flexibility**: Easy to add custom logic (e.g., blacklisting, custom claims)
- **Transparency**: See exactly what happens during authentication
- **Custom Error Messages**: Full control over error responses
- **No Package Dependencies**: Minimal external dependencies (just JWT library)

### Disadvantages
- **More Code**: You must implement everything
- **Maintenance Burden**: You're responsible for security updates
- **Reinventing the Wheel**: Duplicates built-in functionality
- **Potential Bugs**: Easy to introduce security vulnerabilities
- **Testing Complexity**: More code to test
- **Not Idiomatic**: Other .NET developers expect standard approach
- **Missing Features**: No built-in support for Identity, multiple schemes, etc.

### Code Example
```csharp
// Custom JWT Middleware
public class JwtMiddleware
{
    private readonly RequestDelegate _next;
    
    public async Task Invoke(HttpContext context)
    {
        // 1. Extract token
        var token = context.Request.Headers["Authorization"]
            .FirstOrDefault()?.Split(" ").Last();
        
        // 2. Validate token
        var claimsPrincipal = ValidateToken(token);
        
        // 3. Attach to context
        if (claimsPrincipal != null)
        {
            context.User = claimsPrincipal;
        }
        
        // 4. Continue pipeline
        await _next(context);
    }
    
    private ClaimsPrincipal? ValidateToken(string token)
    {
        // Manual validation logic using JwtSecurityTokenHandler
    }
}

// Program.cs
app.UseMiddleware<JwtMiddleware>(); // Custom middleware
app.UseAuthorization(); // Still use built-in authorization
```

---

## When to Use Each Approach

### Use Standard JWT Bearer Authentication When:
- Building a **production application**
- You want **industry best practices**
- Time to market is important
- Team needs **maintainable code**
- Integrating with **ASP.NET Core Identity**
- Need **multiple authentication schemes** (JWT + Cookies + OAuth)
- Want **Microsoft support and updates**

**Example Scenarios:**
- E-commerce API
- Mobile app backend
- Microservices architecture
- Enterprise applications
- SaaS platforms

### Use Custom JWT Middleware When:
- **Learning** how JWT authentication works internally
- Need **very specific custom logic** not supported by built-in authentication
- Building an **educational demo/tutorial**
- Implementing **token blacklisting** or custom validation
- Want to understand **middleware pipeline** in depth
- Prototyping or experimenting with new concepts

**Example Scenarios:**
- Educational projects and tutorials
- Technical interviews (demonstrating knowledge)
- Legacy system migration (gradual transition)
- Custom authentication protocols
- Research and proof-of-concepts

### Hybrid Approach (This Project):
This project uses **BOTH** to demonstrate:
1. How each approach works
2. When to choose one over the other
3. The differences in implementation
4. Educational value of understanding internals vs practical production use

You can switch between approaches using the `UseCustomJwtMiddleware` setting in `appsettings.json`.

---

## Switching Between Approaches

This project allows you to switch between approaches using configuration:

### appsettings.json
```json
{
  "JwtSettings": {
    "UseCustomJwtMiddleware": false,  // false = Standard, true = Custom
    "ClientSecret": "your-secret-key",
    "Issuer": "SecureAPI",
    "Audience": "SecureAPIClients",
    "ExpirationMinutes": 60
  }
}
```

### Program.cs Configuration
The `Program.cs` file automatically configures the appropriate approach based on the setting:

```csharp
var useCustomMiddleware = builder.Configuration
    .GetValue<bool>("JwtSettings:UseCustomJwtMiddleware");

if (useCustomMiddleware)
{
    // Approach 2: Custom Middleware
    app.UseMiddleware<JwtMiddleware>();
}
else
{
    // Approach 1: Standard JWT Bearer
    // AddAuthentication/AddJwtBearer configured in services
    app.UseAuthentication();
}

app.UseAuthorization();
```

### Testing Both Approaches
1. Set `UseCustomJwtMiddleware: false` - Test standard approach
2. Set `UseCustomJwtMiddleware: true` - Test custom approach
3. Both should produce **identical behavior** from API consumer perspective
4. Internal implementation and debugging experience will differ