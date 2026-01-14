# Secure API

## Overview
A comprehensive .NET 8 Web API project demonstrating **TWO different approaches** to JWT (JSON Web Token) authentication in ASP.NET Core. This project is designed as an educational resource to help developers understand both the standard industry approach and the internal workings of JWT authentication.

---

## Features
### 1. **Overview**

- JWT authentication fundamentals and token structure
- **Two implementation approaches**: Standard vs Custom
- Claims-based identity and authorization
- Role-based access control (RBAC)
- Custom authorization policies
- ASP.NET Core middleware pipeline
- Security best practices for token-based authentication
- How to choose the right authentication approach

### 2. **Authentication Approaches**

| Approach | Description
|----------|-------------|
| **Standard JWT Bearer** | Uses built-in ASP.NET Core JWT authentication
| **Custom Middleware** | Manual JWT validation implementation

### 3. **Authorization Patterns Demonstrated**

1. **Public Access** - No authentication required
2. **Basic Authentication** - `[Authorize]` attribute
3. **Role-Based** - `[Authorize(Roles = "Admin")]`
4. **Policy-Based** - `[Authorize(Policy = "AdminPolicy")]`

---

## API Endpoints
| Method | Endpoint                          | Description                                  |
|--------|----------------------------------|----------------------------------------------|
| POST   | /api/auth/login                 | Authenticate and receive a JWT               |
| GET    | /api/auth/profile               | Get user profile (Requires authentication)  |
| GET    | /api/test/public                | Public endpoint (Accessible by anyone)      |
| GET    | /api/test/protected             | Protected endpoint (Requires authentication)|
| GET    | /api/test/admin                 | Admin-only endpoint (Requires Admin role)   |
| GET    | /api/test/admin-policy-secured  | Secured with Admin Policy                   |
| GET    | /api/test/user-policy-secured   | Secured with User Policy                    |

---

## Configuration

### Switching Between Authentication Approaches

Edit `appsettings.json` to toggle between approaches:

```json
{
  "JwtSettings": {
    "UseCustomJwtMiddleware": false,  // false = Standard, true = Custom
    "ClientSecret": "my-super-secure-long-secret-key12345!",
    "Issuer": "SecureAPI",
    "Audience": "SecureAPIClients",
    "ExpirationMinutes": 60
  }
}
```

### Configuration Options

| Property | Description | Default | Production Recommendation |
|----------|-------------|---------|--------------------------|
| `UseCustomJwtMiddleware` | Toggle authentication approach | `false` | `false` (use standard) |
| `ClientSecret` | Secret key for signing tokens | Demo key | 256+ bit random key in Key Vault |
| `Issuer` | Token issuer identifier | `SecureAPI` | Your API domain |
| `Audience` | Token audience identifier | `SecureAPIClients` | Your client app identifier |
| `ExpirationMinutes` | Token lifetime | `60` | 15-60 minutes |

---

## API Endpoints

### Authentication Endpoints

#### POST /api/auth/login
**Purpose**: Authenticate user and receive JWT token

**Request:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Test Accounts:**
- Admin: `admin` / `admin123` (Role: Admin)
- User: `user` / `user123` (Role: User)

#### GET /api/auth/profile
**Purpose**: Get current user's profile information

**Headers:**
```
Authorization: Bearer <your-token>
```

**Response:**
```json
{
  "username": "admin",
  "role": "Admin"
}
```

### Test Endpoints (Authorization Examples)

| Endpoint | Authorization | Who Can Access | Status Without Token |
|----------|---------------|----------------|---------------------|
| `GET /api/test/public` | None | Everyone | 200 OK |
| `GET /api/test/protected` | Any authenticated | admin, user | 401 Unauthorized |
| `GET /api/test/admin` | Admin role | admin only | 401/403 |
| `GET /api/test/admin-policy-secured` | Admin policy | admin only | 401/403 |
| `GET /api/test/user-policy-secured` | User policy | user only | 401/403 |

---

## Testing the API

### Using cURL

1. **Login to get token**
   ```bash
   curl -X POST http://localhost:5000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
   ```

2. **Access protected endpoint**
   ```bash
   curl http://localhost:5000/api/test/protected \
     -H "Authorization: Bearer <your-token>"
   ```

3. **Test public endpoint (no token needed)**
   ```bash
   curl http://localhost:5000/api/test/public
   ```

### Using Swagger UI

1. Navigate to `https://localhost:5001/swagger`
2. Click **POST /api/auth/login**
3. Click **Try it out**
4. Enter credentials: `{"username":"admin","password":"admin123"}`
5. Click **Execute** and copy the token
6. Click **Authorize** button (top right)
7. Enter: `Bearer <your-token>`
8. Now you can test protected endpoints!

### Using Postman

1. Import the endpoints or manually create requests
2. Set up an environment variable for the token
3. Use `{{token}}` in Authorization header: `Bearer {{token}}`
4. Create a pre-request script to auto-login if needed

---

## Security Best Practices

### DO:

- **Use HTTPS** in production (enforce with `app.UseHttpsRedirection()`)
- **Store secrets securely** (Azure Key Vault, AWS Secrets Manager, User Secrets)
- **Use strong secret keys** (256+ bits for HS256)
- **Set appropriate expiration** (15-60 minutes for access tokens)
- **Validate issuer and audience** in production
- **Implement refresh tokens** for long-lived sessions
- **Hash passwords** (bcrypt, Argon2, never plain text)
- **Implement rate limiting** on login endpoints
- **Log security events** (failed logins, token validation failures)
- **Use CORS properly** (don't allow `*` in production)

### DON'T:

- **Never store sensitive data in JWT tokens** (they're base64 encoded, not encrypted)
- **Never commit secrets to source control**
- **Don't set `ValidateIssuerSigningKey = false`** (allows token forgery!)
- **Don't use weak or short secret keys**
- **Don't store tokens in localStorage** (XSS risk - use httpOnly cookies or memory)
- **Don't ignore token expiration** (always validate lifetime)
- **Don't use long expiration times** without refresh tokens
- **Don't skip HTTPS** in production

---

## Extending the Project

### Adding Database Authentication

Replace hardcoded credentials in `AuthController.cs`:

```csharp
// Add Entity Framework Core
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package BCrypt.Net-Next

// Create DbContext
public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
}

// Update AuthController
var user = await _dbContext.Users
    .FirstOrDefaultAsync(u => u.Username == request.Username);

if (user == null || !BCrypt.Verify(request.Password, user.PasswordHash))
    return Unauthorized();
```

### Adding Refresh Tokens

Implement a refresh token flow:

```csharp
[HttpPost("refresh")]
public IActionResult RefreshToken([FromBody] RefreshTokenRequest request)
{
    // Validate refresh token
    var principal = ValidateRefreshToken(request.RefreshToken);
    
    // Generate new access token
    var newAccessToken = _jwtService.GenerateToken(
        principal.Identity.Name, 
        principal.FindFirst(ClaimTypes.Role).Value);
    
    return Ok(new { accessToken = newAccessToken });
}
```

### Adding Email Verification

```csharp
[HttpPost("register")]
public async Task<IActionResult> Register([FromBody] RegisterRequest request)
{
    // Create user
    var user = new User { Username = request.Username, ... };
    
    // Generate email verification token
    var verificationToken = GenerateEmailVerificationToken(user);
    
    // Send email
    await _emailService.SendVerificationEmail(user.Email, verificationToken);
    
    return Ok("Please check your email to verify your account");
}
```

---

## Technologies Used
- .NET Core
- ASP.NET Core Web API

---

## Installation
### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)
- [Postman](https://www.postman.com/) or similar API testing tool (optional)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/andreavallati/SecureAPI.git
   cd SecureAPI
   ```

2. **Restore dependencies**
   ```bash
   dotnet restore
   ```

3. **Run the application**
   ```bash
   dotnet run
   ```

4. **Access Swagger UI**
   ```
   https://localhost:5001/swagger
   ```

---

## Resources

- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT Standard
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725) - RFC 8725
- [ASP.NET Core Authentication](https://learn.microsoft.com/aspnet/core/security/authentication/)
- [JWT.io](https://jwt.io/) - JWT debugging tool
- [Microsoft Docs](https://learn.microsoft.com/aspnet/core/) - ASP.NET Core documentation
- [OWASP](https://owasp.org/) - Security best practices
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

<div align="center">

**Happy Coding!**

</div>
