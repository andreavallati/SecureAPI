using Microsoft.IdentityModel.Tokens;
using SecureAPI.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAPI.Services
{
    public class JwtService : IJwtService
    {
        private readonly string _key;

        public JwtService(string key)
        {
            _key = key;
        }

        public string GenerateToken(string username, string role)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(claims: claims,
                                             expires: DateTime.UtcNow.AddHours(1),
                                             signingCredentials: credentials);

            var result = new JwtSecurityTokenHandler().WriteToken(token);
            return result;
        }
    }
}
