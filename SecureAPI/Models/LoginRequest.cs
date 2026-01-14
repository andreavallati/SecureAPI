using System.ComponentModel.DataAnnotations;

namespace SecureAPI.Models
{
    // ==================================================================================
    // LOGIN REQUEST MODEL - WITH INPUT VALIDATION
    // ==================================================================================
    // This model represents the login request payload with data validation attributes.
    //
    // DATA VALIDATION ATTRIBUTES:
    // - Automatically validated by ASP.NET Core when [ApiController] is used
    // - Returns 400 Bad Request with validation errors if invalid
    // - Reduces boilerplate validation code in controllers
    //
    // BEST PRACTICES:
    // - Always validate user input (never trust client data)
    // - Use appropriate validation attributes for each property
    // - Provide clear error messages for better UX
    // - Consider additional custom validation for complex rules
    //
    // VALIDATION FLOW:
    // 1. Client sends JSON request
    // 2. ASP.NET Core model binding creates LoginRequest object
    // 3. Data annotations are automatically validated
    // 4. If valid: Controller action is called
    // 5. If invalid: 400 Bad Request with validation errors is returned
    // ==================================================================================

    public class LoginRequest
    {
        // ===== USERNAME VALIDATION =====
        // Required: Must be provided
        // MinLength: At least 3 characters
        // MaxLength: No more than 50 characters
        // Pattern: Only letters, numbers, and underscores (optional, commented out)
        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        // Optional: Add regex validation for allowed characters
        // [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
        public string Username { get; set; } = string.Empty;

        // ===== PASSWORD VALIDATION =====
        // Required: Must be provided
        // MinLength: At least 6 characters (increase for production)
        // MaxLength: No more than 100 characters
        //
        // RECOMMENDATIONS:
        // - Minimum 8-12 characters
        // - Require complexity (uppercase, lowercase, numbers, special characters)
        // - Use custom validation attribute for password policy
        // - Never log or expose passwords in error messages
        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be between 6 and 100 characters")]
        // Optional: Add password complexity validation
        // [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        //     ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character")]
        public string Password { get; set; } = string.Empty;
    }
}

