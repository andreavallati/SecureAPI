using Microsoft.AspNetCore.Authorization;

namespace SecureAPI.Authorization
{
    public class RoleRequirement : IAuthorizationRequirement
    {
        public string RequiredRole { get; }
        public RoleRequirement(string role) => RequiredRole = role;
    }
}
