using Microsoft.AspNetCore.Authorization;

namespace SecureAPI.Authorization
{
    // ==================================================================================
    // ROLE REQUIREMENT - CUSTOM AUTHORIZATION REQUIREMENT
    // ==================================================================================
    // This class defines a custom authorization requirement for policy-based authorization.
    //
    // WHAT IT IS:
    // - Implements IAuthorizationRequirement (marker interface)
    // - Represents a requirement that must be satisfied for authorization
    // - Used in custom authorization policies
    //
    // HOW IT WORKS:
    // 1. Define requirement (this class)
    // 2. Create handler (RoleAuthorizationHandler) that evaluates the requirement
    // 3. Register policy in Program.cs that uses this requirement
    // 4. Use [Authorize(Policy = "PolicyName")] on controllers/actions
    //
    // WHEN TO USE:
    // - When built-in [Authorize(Roles = "...")] is not sufficient
    // - Complex authorization logic (multiple conditions)
    // - Resource-based authorization
    // - Custom business rules
    //
    // EXAMPLE POLICIES YOU COULD BUILD:
    // - MinimumAgeRequirement: User must be 18+
    // - PermissionRequirement: User must have specific permission claim
    // - ResourceOwnerRequirement: User must own the resource being accessed
    // - TimeBasedRequirement: Only allow access during business hours
    // - LocationRequirement: Restrict access by IP/geographic location
    //
    // See Documentation/JWT_AUTHENTICATION_APPROACHES.md for more details
    // ==================================================================================

    public class RoleRequirement : IAuthorizationRequirement
    {
        // ===== REQUIRED ROLE =====
        // The role that the user must have to satisfy this requirement
        // Example: "Admin", "User", "Manager", "SuperAdmin"
        public string RequiredRole { get; }

        // ===== CONSTRUCTOR =====
        // Initialize requirement with the role to check
        // This value is provided when creating the policy in Program.cs:
        // options.AddPolicy("AdminPolicy", policy =>
        //     policy.Requirements.Add(new RoleRequirement("Admin")));
        public RoleRequirement(string role) => RequiredRole = role;
    }
}
