# JwtSecurity
User Entity: Represents a user in the system with properties like id, name, username, password, and role.
JwtService: Responsible for generating and validating JWT tokens.
CustomUserDetailsService: Loads user data from the database using the username.
JwtAuthenticationFilter: Intercepts requests and validates JWT tokens.
WebSecurity Configuration: Configures authentication and authorization using Spring Security.
User Authentication Process
Login Request: The user sends their username and password to the server (e.g., via /user/login).
Authentication Manager:
The credentials are passed to Spring Security's authentication manager.
It uses the CustomUserDetailsService to retrieve the user details from the database.
The password is verified using BCryptPasswordEncoder.
1. JWT Token Generation
If the user is authenticated, the JwtService generates a token using:
Username: Used to identify the user.
Expiration Time: Specifies the token's validity period.
Signature: Ensures the token is tamper-proof.
The token is sent back to the user as part of the login response.
2. Token Usage
For subsequent requests, the client includes the JWT token in the Authorization header as Bearer <token>.
3. JWT Validation
When a request reaches the server:
The JwtAuthenticationFilter intercepts it.
It extracts the JWT token from the Authorization header.
The JwtService validates the token:
Checks the signature using the secret key.
Verifies the token is not expired.
Extracts the username and ensures it matches a valid user.
4. Granting Access
If the token is valid:
The CustomUserDetails object is created, containing user details and roles.
A UsernamePasswordAuthenticationToken is populated with this user information.
The request is granted access based on the user's roles and permissions.
If the token is invalid or absent, the request is denied or redirected to a login page.
5. Role-Based Access
Using the roles defined in the User entity, you can control access to different endpoints. For example:
/user/save and /user/login are open to all.
/user/login2 requires a user to have the USER authority.
6. Key Components
JwtService
Handles all JWT-related operations:
Extracting username and claims.
Validating tokens.
Generating tokens with expiration and signature.
JwtAuthenticationFilter
A custom filter that runs once per request to ensure every request has a valid token before processing it further.
CustomUserDetailsService
Integrates with Spring Security to load user details from the database.
WebSecurity Configuration
Configures CORS, CSRF, and session management.
Registers custom authentication filters and providers.
Defines role-based access rules.
