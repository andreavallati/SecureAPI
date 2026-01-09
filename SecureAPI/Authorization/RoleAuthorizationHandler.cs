using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace SecureAPI.Authorization
{
    // ==================================================================================
    // ROLE AUTHORIZATION HANDLER - CUSTOM POLICY EVALUATION
    // ==================================================================================
    // This handler evaluates RoleRequirement for policy-based authorization.
    //
    // AUTHORIZATION HANDLER PATTERN:
    // 1. Requirement: Defines what needs to be checked (RoleRequirement)
    // 2. Handler: Implements the logic to check the requirement (this class)
    // 3. Policy: Combines requirements into a named policy ("AdminPolicy")
    // 4. Attribute: [Authorize(Policy = "PolicyName")] applies the policy
    //
    // EXECUTION FLOW:
    // 1. User makes request with JWT token
    // 2. Middleware validates token and populates HttpContext.User
    // 3. [Authorize(Policy = "AdminPolicy")] triggers policy evaluation
    // 4. ASP.NET Core finds RoleRequirement in the policy
    // 5. This handler is invoked to evaluate the requirement
    // 6. Handler calls context.Succeed() or does nothing (fails)
    // 7. If all requirements succeed, access is granted (200 OK)
    // 8. If any requirement fails, access is denied (403 Forbidden)
    //
    // See Documentation/JWT_AUTHENTICATION_APPROACHES.md for detailed comparison
    // ==================================================================================

    public class RoleAuthorizationHandler : AuthorizationHandler<RoleRequirement>
    {
        // ==================================================================================
        // HANDLE REQUIREMENT ASYNC
        // ==================================================================================
        // This method is called by ASP.NET Core to evaluate the requirement.
        //
        // PARAMETERS:
        // - context: Contains user information and methods to mark requirement as succeeded/failed
        // - requirement: The specific requirement to evaluate (contains RequiredRole)
        //
        // RETURN:
        // - Task.CompletedTask (always)
        // - Success/failure is communicated via context.Succeed() or not calling it
        //
        // IMPORTANT NOTES:
        // - Calling context.Succeed() means the requirement is satisfied
        // - NOT calling context.Succeed() means the requirement failed
        // - You can call context.Fail() to explicitly fail (prevents other handlers from succeeding)
        // - Multiple handlers can be registered for the same requirement
        // - All handlers must succeed for the requirement to be satisfied
        // ==================================================================================
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            RoleRequirement requirement)
        {
            // ===== STEP 1: EXTRACT USER'S ROLE CLAIM =====
            // The User object (ClaimsPrincipal) contains claims from the JWT token
            // Claims were added in JwtService.GenerateToken() when creating the token
            var roleClaim = context.User.Claims
                .FirstOrDefault(c => c.Type == ClaimTypes.Role)?
                .Value;

            // ===== STEP 2: COMPARE WITH REQUIRED ROLE =====
            // Check if user's role matches the required role
            if (roleClaim == requirement.RequiredRole)
            {
                // ===== SUCCESS: REQUIREMENT IS SATISFIED =====
                // Calling context.Succeed() indicates this requirement passed
                // If all requirements in the policy succeed, access is granted
                context.Succeed(requirement);

                // You could also log successful authorization:
                // _logger.LogInformation("User {User} authorized with role {Role}",
                //     context.User.Identity?.Name, roleClaim);
            }
            else
            {
                // ===== FAILURE: REQUIREMENT IS NOT SATISFIED =====
                // We don't call context.Succeed(), which means this requirement failed
                // Authorization will be denied (403 Forbidden)
                //
                // Note: We DON'T call context.Fail() here because:
                // - context.Fail() explicitly fails authorization (prevents other handlers)
                // - Not calling anything allows other handlers to potentially succeed
                // - In this case, there are no other handlers, so not calling = failure

                // You could log authorization failures:
                // _logger.LogWarning("User {User} denied access. Required role: {Required}, User role: {Actual}",
                //     context.User.Identity?.Name, requirement.RequiredRole, roleClaim ?? "None");
            }

            // ===== STEP 3: RETURN COMPLETED TASK =====
            // Authorization handlers must return a Task
            // We use Task.CompletedTask because there's no async work to do
            return Task.CompletedTask;
        }
    }
}
