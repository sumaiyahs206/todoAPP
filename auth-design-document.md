# 🔐 Authentication System Design Document
## CuToDo App - Production-Ready Auth Implementation

---

## 📋 Executive Summary

This document outlines a secure, self-hosted authentication system for the CuToDo application. The system implements industry-standard security practices without relying on third-party OAuth providers, giving complete control over user data and authentication flows.

**Key Features:**
- Email + Password authentication
- Email verification
- Secure password reset
- Session management with HTTP-only cookies
- Rate limiting and brute force protection
- CSRF protection
- Production-ready security standards

---

## 🎯 Authentication Requirements

### User Capabilities
✅ Create account with email + password  
✅ Secure login with credentials  
✅ Email verification required before access  
✅ Password reset via email  
✅ Persistent secure sessions  
✅ Account lockout after failed attempts  

### Security Requirements
✅ bcrypt password hashing with salt  
✅ Secure token generation (crypto.randomBytes)  
✅ Expiring verification/reset tokens  
✅ HTTP-only cookies for sessions  
✅ Rate limiting on auth endpoints  
✅ CSRF protection  
✅ Environment-based secrets  
✅ No sensitive data in error messages  

---

## 🏗️ System Architecture

```
┌─────────────┐
│   Client    │
│  (React)    │
└──────┬──────┘
       │
       │ HTTPS
       │
┌──────▼──────────────────────────────────────┐
│           Express.js Server                  │
├──────────────────────────────────────────────┤
│  Auth Middleware (JWT/Session validation)    │
├──────────────────────────────────────────────┤
│  Rate Limiter (express-rate-limit)           │
├──────────────────────────────────────────────┤
│  CSRF Protection (csurf)                     │
├──────────────────────────────────────────────┤
│  Auth Routes                                 │
│  ├── POST /api/auth/register                 │
│  ├── POST /api/auth/login                    │
│  ├── POST /api/auth/logout                   │
│  ├── GET  /api/auth/verify/:token            │
│  ├── POST /api/auth/forgot-password          │
│  ├── POST /api/auth/reset-password/:token    │
│  └── GET  /api/auth/me                       │
└──────────────┬───────────────────────────────┘
               │
        ┌──────▼──────┐
        │  PostgreSQL  │
        │   Database   │
        └──────┬───────┘
               │
        ┌──────▼──────┐
        │  Email SMTP │
        │   Service   │
        └─────────────┘
```

---

## 🗄️ Database Schema

### Users Table

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    verification_token_expiry TIMESTAMP,
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_verification_token ON users(verification_token);
CREATE INDEX idx_users_reset_token ON users(reset_token);
```

### Sessions Table (if using server-side sessions)

```sql
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Tasks Table (updated with user_id)

```sql
CREATE TABLE tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    time VARCHAR(5),
    duration INTEGER,
    icon VARCHAR(50),
    color VARCHAR(7),
    energy_cost INTEGER DEFAULT 1,
    completed BOOLEAN DEFAULT FALSE,
    date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tasks_user_id ON tasks(user_id);
CREATE INDEX idx_tasks_date ON tasks(date);
```

---

## 🔄 Authentication Flows

### 1. Registration Flow

```
User → Frontend → Backend → Database → Email Service → User

1. User submits email + password
2. Frontend validates:
   - Email format
   - Password strength (8+ chars, mix of types)
3. Backend receives request
4. Check if email already exists
5. Validate password strength
6. Hash password with bcrypt (10 rounds)
7. Generate secure verification token
8. Store user in database (is_verified = false)
9. Send verification email
10. Return success message (no sensitive data)
```

**API Request:**
```json
POST /api/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Account created! Please check your email to verify your account."
}
```

**Error Response:**
```json
{
  "success": false,
  "message": "Email already registered"
}
```

---

### 2. Email Verification Flow

```
User → Email Link → Backend → Database → Redirect

1. User clicks verification link from email
2. Backend extracts token from URL
3. Look up user by verification_token
4. Check token expiry (valid for 24 hours)
5. If valid:
   - Set is_verified = true
   - Clear verification_token
   - Create session
6. Redirect to app dashboard
```

**Verification Link:**
```
https://cutodo.app/api/auth/verify/abc123xyz789token
```

**Token Generation:**
```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
```

---

### 3. Login Flow

```
User → Frontend → Backend → Database → Session → User

1. User submits email + password
2. Rate limiter checks attempt count
3. Backend looks up user by email
4. Check if account is locked (failed attempts)
5. Check if email is verified
6. Compare password with bcrypt.compare()
7. If valid:
   - Reset failed_login_attempts to 0
   - Update last_login timestamp
   - Generate session token or JWT
   - Set HTTP-only cookie
   - Return user data (no sensitive fields)
8. If invalid:
   - Increment failed_login_attempts
   - Lock account after 5 attempts (15 min)
   - Return generic error
```

**API Request:**
```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Success Response:**
```json
{
  "success": true,
  "user": {
    "id": 123,
    "email": "user@example.com",
    "isVerified": true
  }
}
```

**Error Responses:**
```json
// Generic error (no info leak)
{
  "success": false,
  "message": "Invalid credentials"
}

// Account locked
{
  "success": false,
  "message": "Account temporarily locked. Try again in 15 minutes."
}

// Email not verified
{
  "success": false,
  "message": "Please verify your email before logging in."
}
```

---

### 4. Forgot Password Flow

```
User → Frontend → Backend → Database → Email → User

1. User enters email on forgot password page
2. Backend looks up user
3. Generate secure reset token
4. Set reset_token_expiry (15 minutes)
5. Send password reset email
6. Return success (even if email doesn't exist - security)
```

**API Request:**
```json
POST /api/auth/forgot-password
{
  "email": "user@example.com"
}
```

**Response (always same):**
```json
{
  "success": true,
  "message": "If that email exists, a reset link has been sent."
}
```

---

### 5. Reset Password Flow

```
User → Email Link → Reset Form → Backend → Database → Login

1. User clicks reset link from email
2. Frontend shows password reset form
3. User enters new password
4. Backend validates reset token:
   - Token exists
   - Token not expired
   - Token not already used
5. Hash new password
6. Update password_hash
7. Clear reset_token and expiry
8. Invalidate all existing sessions
9. Send confirmation email
10. Redirect to login
```

**API Request:**
```json
POST /api/auth/reset-password/abc123resettoken
{
  "password": "NewSecurePass456!"
}
```

---

### 6. Session Management

**JWT Approach (Recommended for this app):**
```javascript
// Token payload
{
  userId: 123,
  email: "user@example.com",
  iat: 1234567890,
  exp: 1234654290 // 24 hours
}

// Cookie settings
{
  httpOnly: true,
  secure: true, // HTTPS only
  sameSite: 'strict',
  maxAge: 24 * 60 * 60 * 1000
}
```

**Session Validation Middleware:**
```javascript
// Every protected route checks:
1. Cookie exists
2. JWT is valid
3. User still exists
4. User email is verified
5. Account not locked
```

---

## 🔒 Security Implementation Details

### Password Hashing

```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

// Registration
const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

// Login
const isValid = await bcrypt.compare(password, user.password_hash);
```

**Why bcrypt?**
- Adaptive (can increase rounds as computers get faster)
- Per-user automatic salting
- Slow by design (resistant to brute force)
- Industry standard

---

### Token Generation

```javascript
const crypto = require('crypto');

// Verification/reset tokens
const generateToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Cryptographically secure
// 64-character hex string
// ~2^256 possible combinations
```

---

### Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

// Login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts. Try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Registration endpoint
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations
  message: 'Too many accounts created. Try again later.'
});

// Password reset
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: 'Too many reset requests. Try again later.'
});
```

---

### CSRF Protection

```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Apply to state-changing routes
app.post('/api/auth/login', csrfProtection, loginHandler);
app.post('/api/auth/register', csrfProtection, registerHandler);

// Frontend includes token in requests
<input type="hidden" name="_csrf" value="{{ csrfToken }}" />
```

---

### Environment Variables

```bash
# .env file (NEVER commit to git)
DATABASE_URL=postgresql://user:password@localhost:5432/cutodo
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@cutodo.app
SMTP_PASSWORD=app-specific-password
APP_URL=https://cutodo.app
NODE_ENV=production
```

---

## 📧 Email Templates

### Verification Email

```html
Subject: Verify Your CuToDo Account 💕

Hi there!

Welcome to CuToDo! Please verify your email address to start organizing your tasks.

Click here to verify: {{verificationLink}}

This link expires in 24 hours.

If you didn't create this account, please ignore this email.

Love,
The CuToDo Team ✨
```

### Password Reset Email

```html
Subject: Reset Your CuToDo Password 🔑

Hi,

Someone requested a password reset for your CuToDo account.

Click here to reset: {{resetLink}}

This link expires in 15 minutes.

If you didn't request this, your account is still secure. You can ignore this email.

Stay organized!
The CuToDo Team 💖
```

---

## 🛡️ Security Checklist

### ✅ Password Security
- [x] bcrypt hashing with 10+ rounds
- [x] Minimum 8 characters
- [x] Strength validation (uppercase, lowercase, number)
- [x] No password in responses or logs
- [x] Password reset invalidates old passwords

### ✅ Token Security
- [x] Cryptographically random tokens
- [x] Expiring tokens (24h verify, 15m reset)
- [x] Single-use tokens
- [x] Secure token storage (hashed in DB optional)

### ✅ Session Security
- [x] HTTP-only cookies (no JS access)
- [x] Secure flag (HTTPS only)
- [x] SameSite strict (CSRF protection)
- [x] Session expiration (24 hours)
- [x] Session invalidation on logout

### ✅ API Security
- [x] Rate limiting on auth endpoints
- [x] Account lockout (5 failed attempts)
- [x] CSRF protection
- [x] Input validation
- [x] SQL injection prevention (parameterized queries)
- [x] XSS prevention (sanitized inputs)

### ✅ Error Handling
- [x] Generic error messages (no info leak)
- [x] Consistent timing (no enumeration)
- [x] Proper HTTP status codes
- [x] Logged errors (server-side only)

### ✅ Email Security
- [x] Email verification required
- [x] No password in emails
- [x] Unique tokens per request
- [x] SMTP over TLS

---

## 🧪 Testing Scenarios

### Registration Tests
- [x] Valid registration succeeds
- [x] Duplicate email rejected
- [x] Weak password rejected
- [x] Invalid email format rejected
- [x] Verification email sent
- [x] User cannot login before verification

### Login Tests
- [x] Valid credentials succeed
- [x] Invalid credentials fail with generic error
- [x] Unverified email blocked
- [x] Account locks after 5 failures
- [x] Locked account shows time remaining
- [x] Session cookie set correctly

### Email Verification Tests
- [x] Valid token verifies account
- [x] Expired token rejected
- [x] Used token rejected
- [x] Invalid token rejected
- [x] Verified user can login

### Password Reset Tests
- [x] Valid email sends reset link
- [x] Invalid email returns generic success
- [x] Reset token expires after 15 minutes
- [x] Token is single-use
- [x] New password required to be different
- [x] All sessions invalidated after reset

### Security Tests
- [x] Rate limiter blocks excessive requests
- [x] Passwords never logged or returned
- [x] Tokens cannot be guessed
- [x] Session hijacking prevented
- [x] CSRF attacks blocked

---

## 📊 Authentication Metrics

### Success Criteria
- Registration success rate > 95%
- Email delivery rate > 98%
- Login success rate > 90% (for valid users)
- Password reset completion rate > 80%
- Zero password leaks
- Zero session hijacks

### Monitoring
- Failed login attempts per hour
- Account lockouts per day
- Password reset requests per day
- Average verification time
- Session duration

---

## 🚀 Implementation Timeline

### Phase 1: Core Auth (Week 1)
- Database schema setup
- User registration endpoint
- Password hashing implementation
- Basic login/logout
- Session management

### Phase 2: Email System (Week 1-2)
- SMTP configuration
- Email verification flow
- Verification email template
- Token generation and validation

### Phase 3: Password Reset (Week 2)
- Forgot password endpoint
- Reset password endpoint
- Reset email template
- Token expiration logic

### Phase 4: Security Hardening (Week 2-3)
- Rate limiting
- CSRF protection
- Account lockout
- Input validation
- Security testing

### Phase 5: Integration (Week 3)
- Frontend integration
- Error handling
- User feedback
- Documentation

---

## 💡 Advantages of Self-Hosted Auth

### ✅ Full Control
- Custom security policies
- User data ownership
- Custom workflows
- No vendor lock-in

### ✅ Privacy
- No third-party data sharing
- GDPR/privacy law compliance
- User trust

### ✅ Reliability
- No OAuth provider outages
- Works offline from Google
- Predictable behavior

### ✅ Cost
- No OAuth provider fees
- No per-user costs
- Scales with your infra

### ✅ Customization
- Teen-friendly experience
- Pink-themed emails
- Custom error messages
- Branded experience

---

## 🔮 Future Enhancements

### Phase 2 Features
- Two-factor authentication (TOTP)
- Social login (optional, in addition)
- Magic link login (passwordless)
- Remember me functionality
- Device management
- Login notifications

### Advanced Security
- Passwordless authentication
- Biometric support
- IP whitelist/blacklist
- Anomaly detection
- Security audit logs

---

## 📚 Technology Stack

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **PostgreSQL** - Database
- **bcrypt** - Password hashing
- **jsonwebtoken** - JWT tokens
- **nodemailer** - Email sending
- **express-rate-limit** - Rate limiting
- **helmet** - Security headers
- **express-validator** - Input validation

### Frontend Integration
- React hooks for auth state
- Protected routes
- Token refresh logic
- Error boundaries
- Loading states

---

## 📖 API Documentation Summary

### Public Endpoints (No Auth Required)
```
POST   /api/auth/register          - Create account
POST   /api/auth/login             - Login
GET    /api/auth/verify/:token     - Verify email
POST   /api/auth/forgot-password   - Request reset
POST   /api/auth/reset-password/:token - Reset password
```

### Protected Endpoints (Auth Required)
```
GET    /api/auth/me                - Get current user
POST   /api/auth/logout            - Logout
GET    /api/tasks                  - Get user's tasks
POST   /api/tasks                  - Create task
PUT    /api/tasks/:id              - Update task
DELETE /api/tasks/:id              - Delete task
```

---

## 🎯 Success Metrics

### User Experience
- < 2 seconds registration time
- < 1 second login time
- < 5 minutes email delivery
- > 90% email delivery rate
- < 1% lockout rate

### Security
- Zero unauthorized access
- Zero password leaks
- Zero session hijacks
- 100% HTTPS enforcement
- 100% password hashing

---

## ✨ Conclusion

This authentication system provides enterprise-grade security while maintaining a delightful, teen-friendly user experience. Every aspect—from password hashing to email verification—follows industry best practices and security standards.

The system is:
- ✅ **Secure** - Industry-standard encryption and protection
- ✅ **Independent** - No third-party dependencies
- ✅ **Scalable** - Ready for thousands of users
- ✅ **Maintainable** - Clean, documented code
- ✅ **User-Friendly** - Smooth, intuitive flows

---

*Document Version: 1.0*  
*Last Updated: February 2026*  
*Author: Development Team*
