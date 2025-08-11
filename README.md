# passkeys



Content is user-generated and unverified.

Complete FIDO2/WebAuthn API Development Guide
Table of Contents
Introduction
Required APIs
API Payloads Reference
Implementation Guidelines
Security Considerations
Testing and Validation
Introduction
This document provides a comprehensive guide for building FIDO2/WebAuthn compliant passkey authentication systems. It includes all necessary APIs, detailed payload specifications, and implementation guidelines for creating production-ready passkey authentication services.
FIDO2/WebAuthn enables passwordless authentication using public key cryptography, providing stronger security and better user experience compared to traditional password-based authentication.
Required APIs
Core FIDO2/WebAuthn APIs
Registration APIs
POST /webauthn/register/begin - Initiate passkey registration
POST /webauthn/register/finish - Complete passkey registration
GET /webauthn/register/options - Get registration challenge and options
Authentication APIs
POST /webauthn/authenticate/begin - Initiate passkey authentication
POST /webauthn/authenticate/finish - Complete passkey authentication
GET /webauthn/authenticate/options - Get authentication challenge and options
Credential Management APIs
GET /webauthn/credentials - List user's registered passkeys
DELETE /webauthn/credentials/{credentialId} - Remove a passkey
PUT /webauthn/credentials/{credentialId} - Update passkey metadata
GET /webauthn/credentials/{credentialId} - Get passkey details
User Management APIs
Account APIs
POST /users/register - Create new user account
GET /users/profile - Get user profile
PUT /users/profile - Update user profile
DELETE /users/account - Delete user account
Session Management
POST /auth/session - Create authenticated session
DELETE /auth/session - Logout/invalidate session
GET /auth/session/validate - Validate session token
POST /auth/session/refresh - Refresh session token
Device and Authenticator Management
Device Registration
POST /devices/register - Register new device
GET /devices - List user's devices
PUT /devices/{deviceId} - Update device metadata
DELETE /devices/{deviceId} - Remove device
Authenticator Management
GET /authenticators/supported - List supported authenticator types
POST /authenticators/validate - Validate authenticator capabilities
GET /authenticators/attestation - Get attestation requirements
Security and Recovery APIs
Account Recovery
POST /recovery/initiate - Start account recovery process
POST /recovery/verify - Verify recovery credentials
POST /recovery/complete - Complete account recovery
GET /recovery/status - Check recovery status
Security Events
GET /security/events - Get security event log
POST /security/events/report - Report security incident
GET /security/risk-assessment - Get risk assessment
Administrative APIs
Organization Management (for enterprise)
GET /admin/users - List organization users
POST /admin/users/{userId}/disable - Disable user account
GET /admin/policies - Get authentication policies
PUT /admin/policies - Update authentication policies
Analytics and Reporting
GET /analytics/usage - Get usage statistics
GET /analytics/security - Get security metrics
GET /reports/compliance - Generate compliance reports
Integration APIs
Third-Party Identity Providers
POST /oauth/authorize - OAuth authorization endpoint
POST /oauth/token - OAuth token endpoint
GET /oauth/userinfo - OAuth user info endpoint
POST /saml/sso - SAML SSO endpoint
Webhook APIs
POST /webhooks/register - Register webhook endpoint
DELETE /webhooks/{webhookId} - Remove webhook
GET /webhooks/events - List available event types
Platform-Specific APIs
Mobile SDK APIs
POST /mobile/register-push - Register push notifications
GET /mobile/config - Get mobile app configuration
POST /mobile/biometric/verify - Verify biometric authentication
Web SDK APIs
GET /web/config - Get web application configuration
POST /web/csp-report - Content Security Policy reporting
GET /web/well-known/webauthn - WebAuthn configuration
Utility and Support APIs
Health and Monitoring
GET /health - Health check endpoint
GET /status - System status
GET /metrics - Performance metrics
Configuration
GET /config/public - Public configuration
PUT /config/rpid - Update Relying Party ID
GET /config/attestation - Get attestation preferences
Debugging and Development
POST /debug/simulate-auth - Simulate authentication (dev only)
GET /debug/logs - Get debug logs (dev only)
POST /debug/test-authenticator - Test authenticator (dev only)
Optional Advanced APIs
Conditional UI Support
GET /conditional-ui/available - Check conditional UI availability
POST /conditional-ui/register - Register for conditional UI
Enterprise Features
POST /enterprise/bulk-provision - Bulk provision users
GET /enterprise/audit-logs - Get audit logs
POST /enterprise/policy-enforcement - Enforce authentication policies
API Payloads Reference
Core FIDO2/WebAuthn APIs
POST /webauthn/register/begin
Request:

json
{
  "username": "john.doe@example.com",
  "displayName": "John Doe",
  "userVerification": "preferred",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": true,
    "residentKey": "required",
    "userVerification": "required"
  },
  "attestation": "direct"
}
Response:

json
{
  "challenge": "Y2hhbGxlbmdl",
  "rp": {
    "name": "Example Corp",
    "id": "example.com"
  },
  "user": {
    "id": "dXNlcklk",
    "name": "john.doe@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    },
    {
      "type": "public-key",
      "alg": -257
    }
  ],
  "timeout": 60000,
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "ZXhjbHVkZWQ"
    }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": true,
    "residentKey": "required",
    "userVerification": "required"
  },
  "attestation": "direct"
}
POST /webauthn/register/finish
Request:

json
{
  "id": "Y3JlZGVudGlhbElk",
  "rawId": "Y3JlZGVudGlhbElk",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwi",
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0"
  },
  "clientExtensionResults": {}
}
Response:

json
{
  "success": true,
  "credentialId": "Y3JlZGVudGlhbElk",
  "attestation": {
    "verified": true,
    "trustPath": ["intermediate-cert", "root-cert"]
  },
  "credentialInfo": {
    "aaguid": "00000000-0000-0000-0000-000000000000",
    "counter": 0,
    "credentialBackedUp": true,
    "credentialDeviceType": "singleDevice"
  }
}
POST /webauthn/authenticate/begin
Request:

json
{
  "username": "john.doe@example.com",
  "userVerification": "required"
}
Response:

json
{
  "challenge": "YXV0aENoYWxsZW5nZQ",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "Y3JlZGVudGlhbElk",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "required"
}
POST /webauthn/authenticate/finish
Request:

json
{
  "id": "Y3JlZGVudGlhbElk",
  "rawId": "Y3JlZGVudGlhbElk",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0Iiwi",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2M",
    "signature": "MEUCIQDTGVxhrIw2gSANdub7TcNKVYPP",
    "userHandle": "dXNlcklk"
  },
  "clientExtensionResults": {}
}
Response:

json
{
  "success": true,
  "sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "user": {
    "id": "userId",
    "username": "john.doe@example.com",
    "displayName": "John Doe"
  },
  "authInfo": {
    "signCount": 1,
    "credentialBackedUp": true,
    "credentialDeviceType": "singleDevice",
    "flags": {
      "userPresent": true,
      "userVerified": true
    }
  }
}
Credential Management APIs
GET /webauthn/credentials
Response:

json
{
  "credentials": [
    {
      "credentialId": "Y3JlZGVudGlhbElk",
      "nickname": "iPhone TouchID",
      "createdAt": "2025-01-15T10:30:00Z",
      "lastUsed": "2025-08-10T14:20:00Z",
      "deviceInfo": {
        "platform": "iOS",
        "browser": "Safari",
        "aaguid": "08987058-cadc-4b81-b6e1-30de50dcbe96"
      },
      "transports": ["internal"],
      "backupEligible": true,
      "backupState": true
    }
  ]
}
DELETE /webauthn/credentials/{credentialId}
Response:

json
{
  "success": true,
  "message": "Credential successfully removed"
}
User Management APIs
POST /users/register
Request:

json
{
  "email": "john.doe@example.com",
  "displayName": "John Doe",
  "profile": {
    "firstName": "John",
    "lastName": "Doe",
    "locale": "en-US",
    "timezone": "America/New_York"
  }
}
Response:

json
{
  "success": true,
  "userId": "user_123456789",
  "email": "john.doe@example.com",
  "displayName": "John Doe",
  "createdAt": "2025-08-10T15:30:00Z",
  "emailVerified": false
}
GET /users/profile
Response:

json
{
  "userId": "user_123456789",
  "email": "john.doe@example.com",
  "displayName": "John Doe",
  "profile": {
    "firstName": "John",
    "lastName": "Doe",
    "locale": "en-US",
    "timezone": "America/New_York",
    "avatar": "https://example.com/avatars/user123.jpg"
  },
  "security": {
    "twoFactorEnabled": true,
    "passkeysCount": 2,
    "lastPasswordChange": "2025-06-15T10:00:00Z",
    "accountLocked": false
  },
  "preferences": {
    "notifications": {
      "email": true,
      "push": false,
      "sms": false
    },
    "privacy": {
      "profileVisible": false,
      "dataSharing": false
    }
  }
}
Session Management APIs
POST /auth/session
Request:

json
{
  "sessionType": "web",
  "deviceInfo": {
    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "ip": "192.168.1.100",
    "fingerprint": "abc123def456"
  }
}
Response:

json
{
  "sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "refreshToken": "def456ghi789jkl012",
  "expiresIn": 3600,
  "tokenType": "Bearer",
  "scope": "read write"
}
Device Management APIs
POST /devices/register
Request:

json
{
  "deviceName": "John's iPhone 15",
  "deviceType": "mobile",
  "platform": "iOS",
  "platformVersion": "17.5.1",
  "appVersion": "2.1.0",
  "pushToken": "abc123def456ghi789",
  "biometricCapabilities": ["touchID", "faceID"],
  "securityFeatures": {
    "secureEnclave": true,
    "jailbroken": false,
    "debuggingEnabled": false
  }
}
Response:

json
{
  "success": true,
  "deviceId": "device_987654321",
  "registrationToken": "reg_token_abc123",
  "trustedDevice": false,
  "requiresVerification": true
}
Security and Recovery APIs
POST /recovery/initiate
Request:

json
{
  "email": "john.doe@example.com",
  "recoveryMethod": "email",
  "deviceInfo": {
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "ip": "203.0.113.1"
  }
}
Response:

json
{
  "success": true,
  "recoveryId": "recovery_abc123def456",
  "method": "email",
  "expiresIn": 1800,
  "message": "Recovery code sent to email"
}
POST /recovery/verify
Request:

json
{
  "recoveryId": "recovery_abc123def456",
  "verificationCode": "123456",
  "newCredentials": {
    "temporaryPassword": "TempPass123!",
    "requirePasswordChange": true
  }
}
Response:

json
{
  "success": true,
  "temporaryToken": "temp_token_xyz789",
  "nextStep": "password_change",
  "expiresIn": 900
}
Administrative APIs
GET /admin/users
Query Parameters: ?page=1&limit=50&status=active&sortBy=createdAt&sortOrder=desc
Response:

json
{
  "users": [
    {
      "userId": "user_123456789",
      "email": "john.doe@example.com",
      "displayName": "John Doe",
      "status": "active",
      "createdAt": "2025-01-15T10:30:00Z",
      "lastLogin": "2025-08-10T14:20:00Z",
      "credentialsCount": 2,
      "riskScore": "low"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1247,
    "totalPages": 25
  }
}
PUT /admin/policies
Request:

json
{
  "authentication": {
    "requirePasskey": true,
    "allowPasswordFallback": false,
    "sessionTimeout": 3600,
    "maxConcurrentSessions": 3
  },
  "registration": {
    "requireEmailVerification": true,
    "allowedDomains": ["example.com", "partner.com"],
    "minimumPasskeyRequirement": 1
  },
  "security": {
    "riskBasedAuthentication": true,
    "deviceTrust": {
      "enabled": true,
      "trustPeriod": 2592000
    },
    "ipWhitelisting": {
      "enabled": false,
      "ranges": []
    }
  }
}
Response:

json
{
  "success": true,
  "policyId": "policy_abc123",
  "updatedAt": "2025-08-10T15:45:00Z",
  "effectiveDate": "2025-08-10T16:00:00Z"
}
Integration APIs
POST /oauth/token
Request:

json
{
  "grant_type": "authorization_code",
  "code": "auth_code_abc123",
  "client_id": "client_123456789",
  "client_secret": "secret_xyz789",
  "redirect_uri": "https://client.example.com/callback"
}
Response:

json
{
  "access_token": "access_token_abc123def456",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_ghi789jkl012",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
}
Implementation Guidelines
1. WebAuthn Specification Compliance
Core Requirements:
Implement WebAuthn Level 2 specification
Support both platform and roaming authenticators
Handle attestation verification properly
Implement proper challenge generation and validation
Supported Algorithms:
ES256 (ECDSA with P-256 curve)
RS256 (RSA with SHA-256)
EdDSA (Ed25519 signature)
2. Database Schema Considerations
Users Table:

sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  display_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'active'
);
Credentials Table:

sql
CREATE TABLE webauthn_credentials (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  credential_id BYTEA UNIQUE NOT NULL,
  public_key BYTEA NOT NULL,
  counter BIGINT DEFAULT 0,
  aaguid UUID,
  transport TEXT[],
  backup_eligible BOOLEAN DEFAULT FALSE,
  backup_state BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP
);
3. Security Best Practices
Challenge Generation:
Use cryptographically secure random number generator
Minimum 32 bytes of entropy
Set appropriate timeout (30-120 seconds)
Store challenges securely with expiration
Origin Validation:
Verify origin matches expected RP ID
Implement proper CORS policies
Validate client data JSON structure
Attestation Handling:
Support "none", "indirect", and "direct" attestation
Implement certificate chain validation
Handle AAGUID-based device identification
4. Error Handling
Common Error Codes:
INVALID_CHALLENGE - Challenge expired or invalid
CREDENTIAL_NOT_FOUND - Credential doesn't exist
USER_VERIFICATION_FAILED - Biometric/PIN check failed
ATTESTATION_INVALID - Attestation verification failed
ORIGIN_MISMATCH - Origin doesn't match RP ID
5. Rate Limiting
Implement rate limiting for:
Registration attempts (5 per hour per IP)
Authentication attempts (10 per minute per user)
Recovery requests (3 per hour per email)
Security Considerations
1. Cryptographic Requirements
Key Generation:
Use hardware-backed key storage when available
Support P-256 and P-384 elliptic curves
Implement proper key attestation verification
Challenge Security:
Generate unique challenges for each ceremony
Use CSPRNG for challenge generation
Implement challenge replay protection
2. Privacy Protection
User Identification:
Use opaque user handles instead of email addresses
Implement user handle rotation capabilities
Support anonymous authentication flows
Data Minimization:
Only collect necessary user information
Implement data retention policies
Support user data deletion requests
3. Attack Mitigation
Phishing Protection:
Enforce origin validation
Implement certificate pinning for mobile apps
Use FIDO AppID extension for legacy support
Credential Stuffing:
Monitor for suspicious login patterns
Implement device fingerprinting
Use risk-based authentication
4. Compliance Requirements
GDPR Compliance:
Implement consent management
Support data portability requests
Maintain audit logs for data processing
SOC 2 Requirements:
Implement comprehensive logging
Monitor security events
Regular security assessments
Testing and Validation
1. Unit Testing
Registration Flow Tests:

javascript
describe('WebAuthn Registration', () => {
  test('should generate valid challenge', async () => {
    const options = await webauthn.generateRegistrationOptions(user);
    expect(options.challenge).toBeDefined();
    expect(options.challenge.length).toBeGreaterThan(32);
  });

  test('should verify valid attestation', async () => {
    const result = await webauthn.verifyRegistrationResponse(response);
    expect(result.verified).toBe(true);
    expect(result.credentialId).toBeDefined();
  });
});
2. Integration Testing
End-to-End Authentication Flow:
Test complete registration workflow
Verify authentication with different authenticators
Test error handling scenarios
Validate session management
3. Security Testing
Penetration Testing:
Test for injection vulnerabilities
Verify authentication bypass attempts
Test session management security
Validate input sanitization
Compliance Testing:
FIDO2 conformance testing
WebAuthn interoperability testing
Cross-browser compatibility testing
4. Performance Testing
Load Testing:
Test concurrent registration requests
Verify authentication performance under load
Monitor database query performance
Test API rate limiting effectiveness
Error Response Format
All APIs use consistent error format:

json
{
  "error": {
    "code": "INVALID_CREDENTIAL",
    "message": "The provided credential is invalid or expired",
    "details": {
      "field": "credentialId",
      "reason": "credential_not_found"
    },
    "timestamp": "2025-08-10T15:30:00Z",
    "requestId": "req_abc123def456"
  }
}
Common HTTP Status Codes
200 OK - Successful operation
201 Created - Resource created successfully
400 Bad Request - Invalid request payload
401 Unauthorized - Authentication required
403 Forbidden - Insufficient permissions
404 Not Found - Resource not found
409 Conflict - Resource already exists
422 Unprocessable Entity - Validation error
429 Too Many Requests - Rate limit exceeded
500 Internal Server Error - Server error

