namespace SecureAPI.Models
{
    // ==================================================================================
    // API ERROR MODEL - STANDARDIZED ERROR RESPONSE
    // ==================================================================================
    // This model provides a consistent error response format across all endpoints.
    //
    // USAGE:
    // return Unauthorized(new ApiError
    // {
    //     StatusCode = StatusCodes.Status401Unauthorized,
    //     Message = "Invalid credentials",
    //     Details = "The username or password you entered is incorrect"
    // });
    //
    // RESPONSE FORMAT:
    // {
    //   "statusCode": 401,
    //   "message": "Invalid credentials",
    //   "details": "The username or password you entered is incorrect"
    // }
    // ==================================================================================

    public class ApiError
    {
        // ===== STATUS CODE =====
        // HTTP status code (400, 401, 403, 404, 500, etc.)
        // Helps clients understand the type of error
        public int StatusCode { get; set; }

        // ===== MESSAGE =====
        // Short, user-friendly error message
        // Example: "Authentication failed", "Invalid input", "Resource not found"
        public string Message { get; set; } = string.Empty;

        // ===== DETAILS (OPTIONAL) =====
        // Additional context or technical details
        // Example: "Token has expired at 2024-01-15 10:30:00 UTC"
        // Note: Be careful not to expose sensitive information
        public string? Details { get; set; }

        // ===== CONVENIENCE FACTORY METHODS =====
        // These static methods make it easy to create common error responses

        /// <summary>
        /// Creates a 400 Bad Request error response
        /// </summary>
        public static ApiError BadRequest(string message, string? details = null)
            => new() { StatusCode = 400, Message = message, Details = details };

        /// <summary>
        /// Creates a 401 Unauthorized error response
        /// </summary>
        public static ApiError Unauthorized(string message, string? details = null)
            => new() { StatusCode = 401, Message = message, Details = details };

        /// <summary>
        /// Creates a 403 Forbidden error response
        /// </summary>
        public static ApiError Forbidden(string message, string? details = null)
            => new() { StatusCode = 403, Message = message, Details = details };

        /// <summary>
        /// Creates a 404 Not Found error response
        /// </summary>
        public static ApiError NotFound(string message, string? details = null)
            => new() { StatusCode = 404, Message = message, Details = details };

        /// <summary>
        /// Creates a 500 Internal Server Error response
        /// </summary>
        public static ApiError InternalServerError(string message, string? details = null)
            => new() { StatusCode = 500, Message = message, Details = details };
    }
}
