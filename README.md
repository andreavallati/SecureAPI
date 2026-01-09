# Secure API

## Overview
SecureAPI is a .NET Core Web API that provides authentication and authorization using JWT (JSON Web Token). The project includes role-based access control and secure endpoints. It is designed to offer a secure and scalable authentication system for APIs.

---

## Features
- JWT-based authentication
- Role-based authorization
- Secure API endpoints with access control
- Configurable settings via `appsettings.json`
- Middleware for handling authentication
- Extensible service-based architecture
- Error handling and logging support

---

## Technologies Used
- .NET Core
- ASP.NET Core Web API

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

## Installation
### Prerequisites
- .NET SDK 6.0 or later
- SQL Server (if using database authentication)

### Steps
1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd SecureAPI
   ```
2. Install dependencies:
   ```sh
   dotnet restore
   ```
3. Configure `appsettings.json` with your preferred JWT settings.
4. If using a database, apply migrations:
   ```sh
   dotnet ef database update
   ```

## Usage
### Running the API
1. Start the application:
   ```sh
   dotnet run
   ```
2. The API will be available at:
   ```sh
   https://localhost:YourPort
   ```

### Authentication Flow
1. Register/Login by sending a POST request:
   ```sh
   POST /api/auth/login
   ```
   Example request body:
   ```json
   {
     "username": "testuser",
     "password": "password123"
   }
   ```
2. The API will respond with a JWT token:
   ```json
   {
     "token": "your.jwt.token.here"
   }
   ```
3. Use the token in the `Authorization` header to access protected endpoints:
   ```sh
   GET /api/protected
   Authorization: Bearer your.jwt.token.here
   ```

## Configuration
- **JWT settings**: Defined in `appsettings.json`
- **Roles and policies**: Managed in `RoleAuthorizationHandler.cs`
- **Database connection**: Configured in `appsettings.json` if applicable

---

<div align="center">

**Happy Coding!**

</div>
