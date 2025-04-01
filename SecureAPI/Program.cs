using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using SecureAPI.Authorization;
using SecureAPI.Interfaces;
using SecureAPI.Middleware;
using SecureAPI.Models;
using SecureAPI.Services;

var builder = WebApplication.CreateBuilder(args);

// Bind JwtSettings from configuration
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminPolicy", policy => policy.Requirements.Add(new RoleRequirement("Admin")));
    options.AddPolicy("UserPolicy", policy => policy.Requirements.Add(new RoleRequirement("User")));
});

builder.Services.AddSingleton<IAuthorizationHandler, RoleAuthorizationHandler>();

builder.Services.AddSingleton<IJwtService>(sp =>
{
    var jwtSettings = sp.GetRequiredService<IOptions<JwtSettings>>().Value;
    return new JwtService(jwtSettings.ClientSecret);
});

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Use custom JWT Middleware before authentication
app.UseMiddleware<JwtMiddleware>();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

await app.RunAsync();