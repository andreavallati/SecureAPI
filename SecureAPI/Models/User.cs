namespace SecureAPI.Models
{
    // ==================================================================================
    // USER MODEL
    // ==================================================================================
    // This model represents a user entity in the system.
    //
    // CURRENT STATUS: NOT CURRENTLY USED IN CODEBASE
    //
    // FUTURE USAGE SCENARIOS:
    // This model is prepared for future enhancements and can be used when implementing:
    //
    // 1. DATABASE INTEGRATION:
    //    - Entity Framework Core model for Users table
    //    - Replace hardcoded credentials with database queries
    //    - Example:
    //      public class ApplicationDbContext : DbContext
    //      {
    //          public DbSet<User> Users { get; set; }
    //      }
    //
    // 2. USER REPOSITORY PATTERN:
    //    - IUserRepository interface for user data operations
    //    - UserRepository implementation for CRUD operations
    //    - Example:
    //      public interface IUserRepository
    //      {
    //          Task<User?> GetByUsernameAsync(string username);
    //          Task<User> CreateAsync(User user);
    //      }
    //
    // 3. ASP.NET CORE IDENTITY INTEGRATION:
    //    - Extend IdentityUser with custom properties
    //    - Example:
    //      public class User : IdentityUser
    //      {
    //          // Custom properties here
    //      }
    //
    // 4. USER REGISTRATION:
    //    - Add registration endpoint that creates new User entities
    //    - Hash passwords using BCrypt or Argon2
    //    - Store users in database
    //
    // 5. USER PROFILE MANAGEMENT:
    //    - Store additional user information (email, phone, preferences)
    //    - Update profile endpoint
    //    - User settings and preferences
    //
    // ENHANCEMENTS:
    // When implementing, consider adding:
    // - [Key] attribute for Id property (Entity Framework)
    // - [MaxLength] attributes for database constraints
    // - CreatedAt, UpdatedAt timestamps
    // - IsActive, IsEmailVerified flags
    // - Navigation properties for related entities
    // - Password should NEVER be stored in plain text (use hashing)
    //
    // See AuthController.Login() for current hardcoded user authentication
    // ==================================================================================

    public class User
    {
        // User identifier (primary key when using database)
        // Example: Add [Key] attribute for Entity Framework
        // public int Id { get; set; }

        // Username for authentication
        public string Username { get; set; } = string.Empty;

        // Password (IMPORTANT: This should be a hashed password, never plain text!)
        // Consider: PasswordHash property instead, use BCrypt/Argon2 for hashing
        public string Password { get; set; } = string.Empty;

        // User's role for authorization
        // Default: "User" role assigned to new users
        // Examples: "Admin", "User", "Manager", "SuperAdmin"
        public string Role { get; set; } = "User";

        // Additional properties you might add:
        // public string Email { get; set; } = string.Empty;
        // public string? PhoneNumber { get; set; }
        // public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        // public DateTime? LastLoginAt { get; set; }
        // public bool IsActive { get; set; } = true;
        // public bool IsEmailVerified { get; set; } = false;
    }
}

