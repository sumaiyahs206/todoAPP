# 🔒 Security Implementation Explained

Detailed explanation of every security measure in the CuToDo authentication system.

---

## 🎯 Security Goals

1. **Confidentiality** - User data stays private
2. **Integrity** - Data cannot be tampered with
3. **Availability** - System remains accessible to legitimate users
4. **Authentication** - Users are who they claim to be
5. **Authorization** - Users can only access their own data

---

## 🔐 Password Security

### bcrypt Hashing

**Why bcrypt?**
```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

// Registration
const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
// Result: $2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

**How it works:**
1. **Salt Generation**: Random string unique to each password
2. **Hashing**: Password + salt → irreversible hash
3. **Cost Factor**: 10 rounds = 2^10 iterations (1024 iterations)
4. **Adaptive**: Can increase rounds as computers get faster

**Why NOT use MD5, SHA256, etc.?**
- Too fast (billions of hashes per second)
- No built-in salt
- Not designed for passwords
- Vulnerable to rainbow tables

**Security Properties:**
- ✅ One-way (cannot reverse)
- ✅ Unique per user (random salt)
- ✅ Slow by design (prevents brute force)
- ✅ Future-proof (adaptive cost)

### Password Validation

```javascript
// Minimum requirements enforced
body('password')
  .isLength({ min: 8 })
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
```

**Requirements:**
- At least 8 characters
- Contains lowercase letter
- Contains uppercase letter
- Contains number

**Why these rules?**
- 8+ chars = 218 trillion combinations (letters + numbers)
- Mixed case + numbers = harder to crack
- Prevents common weak passwords

**Password Strength Examples:**
```
❌ "password"      - Too common
❌ "12345678"      - No letters
❌ "Password"      - No numbers
✅ "MyPass123"     - Meets requirements
✅ "C00lP@ss!"     - Strong
```

---

## 🎟️ Token Security

### JWT (JSON Web Tokens)

**Structure:**
```
header.payload.signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VySWQiOjEyMywiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**How JWT Works:**
1. **Server creates token** with user data
2. **Signs with secret** (HMAC-SHA256)
3. **Sends to client** in HTTP-only cookie
4. **Client includes in requests** (automatic)
5. **Server verifies signature** before accepting

**Security Features:**
- ✅ Tamper-proof (signature verification)
- ✅ Stateless (no database lookup needed)
- ✅ Self-contained (includes user info)
- ✅ Expiring (24 hour lifetime)

**JWT Secret:**
```bash
# Minimum 32 characters
JWT_SECRET=your-super-secret-jwt-key-min-32-characters

# Generate secure secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Verification/Reset Tokens

```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
// Result: 64-character hex string
// Example: 3a8f5c2d9e1b7f4a6c8d0e2f1a3b5c7d9e1f2a4b6c8d0e2f1a3b5c7d9e1f2a4b
```

**Properties:**
- 32 bytes = 256 bits of entropy
- ~1.16 × 10^77 possible combinations
- Cryptographically secure random
- Time-limited (15-24 hours)
- Single-use only

**Token Lifecycle:**
```
1. Generate → Store in DB → Send in email
2. User clicks link
3. Verify token exists & not expired
4. Perform action (verify/reset)
5. Delete token (single-use)
```

---

## 🍪 Cookie Security

### HTTP-Only Cookies

```javascript
res.cookie('auth_token', token, {
  httpOnly: true,      // Cannot be accessed by JavaScript
  secure: true,        // HTTPS only
  sameSite: 'strict',  // CSRF protection
  maxAge: 24 * 60 * 60 * 1000  // 24 hours
});
```

**Why HTTP-only?**
```javascript
// This will NOT work (httpOnly protects against XSS)
document.cookie;  // Cannot access auth_token
localStorage.getItem('token');  // No token here either!
```

**Protection Against:**
- ✅ XSS (Cross-Site Scripting)
- ✅ JavaScript-based attacks
- ✅ Token theft via malicious scripts

**Secure Flag:**
- Only sent over HTTPS
- Prevents interception over HTTP

**SameSite Strict:**
- Cookie not sent with cross-site requests
- Protects against CSRF attacks

---

## 🚫 Rate Limiting

### Login Rate Limiting

```javascript
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 attempts
  message: 'Too many login attempts'
});
```

**How it works:**
1. Tracks requests by IP address
2. Counts attempts in time window
3. Blocks after exceeding limit
4. Resets after time window

**Protection:**
- Prevents brute force password guessing
- Slows down automated attacks
- Protects against account enumeration

**Example Attack Prevention:**
```
Attempt 1: ❌ Wrong password
Attempt 2: ❌ Wrong password
Attempt 3: ❌ Wrong password
Attempt 4: ❌ Wrong password
Attempt 5: ❌ Wrong password
Attempt 6: 🚫 BLOCKED - Try again in 15 minutes

Attacker needs: 5 attempts × 15 min = 75 min per 5 attempts
To try 1000 passwords: 1000 ÷ 5 × 15 = 3000 minutes (50 hours)
```

### Account Lockout

```javascript
// After 5 failed attempts
failed_login_attempts >= 5
→ Lock for 15 minutes
```

**Dual Protection:**
- Rate limiter (by IP)
- Account lockout (by user)

**Why both?**
- Rate limiter: Protects against distributed attacks
- Account lockout: Protects specific accounts

---

## 🛡️ SQL Injection Prevention

### Parameterized Queries

**❌ VULNERABLE (Never do this):**
```javascript
// User input directly in query
const query = `SELECT * FROM users WHERE email = '${email}'`;
```

**Attack:**
```javascript
email = "admin@example.com' OR '1'='1"
// Results in: SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1'
// Returns ALL users!
```

**✅ SECURE (Our implementation):**
```javascript
const query = 'SELECT * FROM users WHERE email = $1';
const result = await pool.query(query, [email]);
```

**Protection:**
- Parameters are escaped automatically
- SQL engine treats input as data, not code
- Impossible to break out of parameter

---

## 🔍 Information Leakage Prevention

### Generic Error Messages

**❌ BAD (leaks info):**
```javascript
// Login fails
if (!user) {
  return res.json({ error: "Email not found" });
}
if (!validPassword) {
  return res.json({ error: "Wrong password" });
}
```

**Attack:**
```
Attacker tries: test@example.com
Response: "Email not found"
→ Attacker now knows this email isn't registered

Attacker tries: admin@example.com
Response: "Wrong password"
→ Attacker now knows admin@example.com IS registered!
```

**✅ GOOD (our implementation):**
```javascript
// Always return same message
return res.json({ error: "Invalid credentials" });
```

**Benefits:**
- Cannot enumerate valid emails
- Cannot distinguish between wrong email vs wrong password
- Forces attacker to try full combinations

### Password Reset

**❌ BAD:**
```javascript
if (!userExists) {
  return res.json({ error: "Email not found" });
}
```

**✅ GOOD:**
```javascript
// Always return success (even if email doesn't exist)
return res.json({ 
  success: true, 
  message: "If that email exists, a reset link has been sent." 
});
```

---

## 🌐 CORS Security

```javascript
app.use(cors({
  origin: 'https://cutodo.app',  // Only allow our frontend
  credentials: true               // Allow cookies
}));
```

**Without CORS:**
- Any website could call our API
- Attacker's site could make requests as user

**With CORS:**
- Only whitelisted origins accepted
- Browser blocks unauthorized sites

---

## 🔒 CSRF Protection

### What is CSRF?

**Attack Scenario:**
```html
<!-- Attacker's website: evil.com -->
<form action="https://cutodo.app/api/tasks" method="POST">
  <input type="hidden" name="title" value="Pwned!">
  <script>document.forms[0].submit();</script>
</form>

<!-- If user is logged into CuToDo, this creates a task! -->
```

### Our Protection

**1. SameSite Cookies:**
```javascript
sameSite: 'strict'  // Cookie not sent from evil.com
```

**2. CSRF Tokens (if needed):**
```javascript
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// Token required for state-changing operations
```

---

## ✉️ Email Security

### Verification Required

**Why?**
1. Confirms email ownership
2. Prevents fake accounts
3. Enables password recovery
4. Prevents spam signups

**Flow:**
```
1. User signs up → is_verified = FALSE
2. Email sent with token
3. User clicks link → is_verified = TRUE
4. Only then can login
```

### Token Expiry

```javascript
verification_token_expiry = NOW() + 24 hours
reset_token_expiry = NOW() + 15 minutes
```

**Why expire?**
- Limits attack window
- Forces fresh tokens for security
- Verification: 24h (convenience)
- Reset: 15min (security critical)

---

## 🔑 Session Management

### JWT vs Server Sessions

**We use JWT because:**
- ✅ Stateless (no DB lookup per request)
- ✅ Scalable (no shared session store)
- ✅ Works across services
- ✅ Built-in expiration

**Security Considerations:**
```javascript
// JWT payload
{
  userId: 123,
  email: "user@example.com",
  iat: 1234567890,  // Issued at
  exp: 1234654290   // Expires at (24h)
}
```

**Cannot include:**
- ❌ Passwords
- ❌ Sensitive personal data
- ❌ API keys

**Can include:**
- ✅ User ID
- ✅ Email
- ✅ Role/permissions

### Session Invalidation

**Logout:**
```javascript
// Clear cookie
res.clearCookie('auth_token');

// JWT is now invalid (client-side)
// Server will reject it even if sent
```

**Password Reset:**
```javascript
// When password changes, user must re-login
// Old JWT tokens become invalid
// (Token contains old password hash signature)
```

---

## 🎭 Account Enumeration Prevention

### Registration

**Attack:**
```
Try: admin@example.com
Response: "Email already registered"
→ Attacker knows admin@example.com exists
```

**Our Protection:**
```javascript
// Still return same message, but fail silently
if (emailExists) {
  return res.json({ 
    success: true,
    message: "Account created! Check your email."
  });
  // Don't actually send email
}
```

**Trade-offs:**
- More secure
- Slightly worse UX (user doesn't know email is taken)
- Prevents email harvesting

---

## 🛠️ Input Validation

### Email Validation

```javascript
body('email')
  .isEmail()           // RFC compliant
  .normalizeEmail()    // Lowercase, trim
```

**Normalization:**
```
Input: "  User@EXAMPLE.com  "
Normalized: "user@example.com"
```

**Benefits:**
- Consistent storage
- Prevents duplicates (User@example.com vs user@example.com)
- Case-insensitive login

### SQL Injection Prevention

**Already covered with parameterized queries!**

### XSS Prevention

```javascript
// Express automatically escapes HTML
// Don't use:
res.send(`<h1>${userInput}</h1>`);  // ❌ Vulnerable

// Use:
res.json({ title: userInput });     // ✅ Safe
```

---

## 📊 Security Monitoring

### What to Log

**✅ DO log:**
- Failed login attempts
- Account lockouts
- Password reset requests
- Email verification attempts
- API errors

**❌ DON'T log:**
- Passwords (even hashed)
- Tokens
- Session IDs
- Sensitive user data

**Example:**
```javascript
// ✅ GOOD
logger.info('Failed login', { email, ip, timestamp });

// ❌ BAD
logger.info('Failed login', { email, password, token });
```

---

## 🚨 Incident Response

### Compromised JWT Secret

**If JWT_SECRET is leaked:**
```bash
1. Generate new secret immediately
2. Update .env file
3. Restart server
4. All existing sessions become invalid
5. Users must re-login
```

### Compromised Database

**If database is accessed:**
```bash
1. All passwords are safe (bcrypt hashed)
2. Rotate JWT_SECRET
3. Invalidate all sessions
4. Force password resets
5. Notify users
6. Audit logs for unauthorized access
```

### Email Account Compromised

**If SMTP account is hacked:**
```bash
1. Change SMTP password
2. Update .env
3. Check for unauthorized emails sent
4. Notify affected users
5. Consider 2FA for SMTP account
```

---

## ✅ Security Checklist

### Development
- [x] bcrypt password hashing (10 rounds)
- [x] JWT tokens with expiration
- [x] HTTP-only cookies
- [x] Rate limiting
- [x] Parameterized SQL queries
- [x] Input validation
- [x] Email verification
- [x] Generic error messages

### Production
- [ ] HTTPS enabled (SSL certificate)
- [ ] Secure cookies (secure: true)
- [ ] Environment variables (no hardcoded secrets)
- [ ] Database SSL/TLS
- [ ] Regular backups
- [ ] Error monitoring (Sentry)
- [ ] Security headers (Helmet)
- [ ] CORS configured properly
- [ ] Firewall rules
- [ ] Regular security audits

---

## 🎓 Security Principles Applied

### Defense in Depth
Multiple layers of security:
1. Rate limiting (network layer)
2. Input validation (application layer)
3. Parameterized queries (data layer)
4. bcrypt hashing (storage layer)

### Principle of Least Privilege
- Users can only access their own data
- Database user has minimum required permissions
- API keys scoped to specific services

### Fail Securely
- On error, deny access (not grant)
- Invalid token → reject request
- Database error → don't expose details

### Secure by Default
- Email verification required
- Secure cookies in production
- Rate limiting active
- Password strength enforced

---

## 📚 Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [bcrypt Explained](https://en.wikipedia.org/wiki/Bcrypt)
- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)

---

**Remember: Security is a process, not a product. Stay updated, audit regularly, and always assume attackers are trying! 🛡️**
