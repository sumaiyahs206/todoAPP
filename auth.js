// routes/auth.js - Authentication Routes
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { pool } = require('../server');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/email');
const { authenticateToken } = require('../middleware/auth');

const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '24h';

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many login attempts' }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many registrations' }
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many reset requests' }
});

// ============================================
// REGISTER
// ============================================
router.post('/register',
  registerLimiter,
  [
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Invalid email address'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must contain uppercase, lowercase, and number')
  ],
  async (req, res) => {
    try {
      // Validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: errors.array()[0].msg
        });
      }

      const { email, password } = req.body;

      // Check if user exists
      const existingUser = await pool.query(
        'SELECT id FROM users WHERE email = $1',
        [email]
      );

      if (existingUser.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Email already registered'
        });
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Create user
      const result = await pool.query(
        `INSERT INTO users (
          email, 
          password_hash, 
          verification_token, 
          verification_token_expiry
        ) VALUES ($1, $2, $3, $4) 
        RETURNING id, email`,
        [email, passwordHash, verificationToken, verificationExpiry]
      );

      const newUser = result.rows[0];

      // Send verification email
      const verificationLink = `${process.env.APP_URL}/api/auth/verify/${verificationToken}`;
      await sendVerificationEmail(email, verificationLink);

      res.status(201).json({
        success: true,
        message: 'Account created! Please check your email to verify your account. 💕'
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Registration failed. Please try again.'
      });
    }
  }
);

// ============================================
// EMAIL VERIFICATION
// ============================================
router.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Find user with this token
    const result = await pool.query(
      `SELECT id, email, verification_token_expiry 
       FROM users 
       WHERE verification_token = $1 
       AND is_verified = false`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send(`
        <html>
          <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>❌ Invalid Verification Link</h1>
            <p>This link is invalid or has already been used.</p>
            <a href="${process.env.CLIENT_URL}/login">Go to Login</a>
          </body>
        </html>
      `);
    }

    const user = result.rows[0];

    // Check if token expired
    if (new Date() > new Date(user.verification_token_expiry)) {
      return res.status(400).send(`
        <html>
          <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>⏰ Link Expired</h1>
            <p>This verification link has expired. Please request a new one.</p>
            <a href="${process.env.CLIENT_URL}/resend-verification">Resend Link</a>
          </body>
        </html>
      `);
    }

    // Verify user
    await pool.query(
      `UPDATE users 
       SET is_verified = true, 
           verification_token = NULL, 
           verification_token_expiry = NULL 
       WHERE id = $1`,
      [user.id]
    );

    // Generate JWT and set cookie
    const jwtToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.cookie('auth_token', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    // Redirect to app
    res.send(`
      <html>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
          <h1>✅ Email Verified!</h1>
          <p>Your account has been verified successfully. 💕</p>
          <p>Redirecting to app...</p>
          <script>
            setTimeout(() => {
              window.location.href = '${process.env.CLIENT_URL}/dashboard';
            }, 2000);
          </script>
        </body>
      </html>
    `);

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).send('Verification failed');
  }
});

// ============================================
// LOGIN
// ============================================
router.post('/login',
  loginLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      const { email, password } = req.body;

      // Get user
      const result = await pool.query(
        `SELECT id, email, password_hash, is_verified, 
                failed_login_attempts, account_locked_until 
         FROM users 
         WHERE email = $1`,
        [email]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      const user = result.rows[0];

      // Check if account is locked
      if (user.account_locked_until && new Date() < new Date(user.account_locked_until)) {
        const minutesLeft = Math.ceil((new Date(user.account_locked_until) - new Date()) / 60000);
        return res.status(423).json({
          success: false,
          message: `Account temporarily locked. Try again in ${minutesLeft} minutes.`
        });
      }

      // Check if verified
      if (!user.is_verified) {
        return res.status(403).json({
          success: false,
          message: 'Please verify your email before logging in.'
        });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password_hash);

      if (!isValidPassword) {
        // Increment failed attempts
        const newAttempts = user.failed_login_attempts + 1;
        const lockUntil = newAttempts >= 5 
          ? new Date(Date.now() + 15 * 60 * 1000) 
          : null;

        await pool.query(
          `UPDATE users 
           SET failed_login_attempts = $1,
               account_locked_until = $2
           WHERE id = $3`,
          [newAttempts, lockUntil, user.id]
        );

        if (newAttempts >= 5) {
          return res.status(423).json({
            success: false,
            message: 'Too many failed attempts. Account locked for 15 minutes.'
          });
        }

        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      // Reset failed attempts and update last login
      await pool.query(
        `UPDATE users 
         SET failed_login_attempts = 0,
             account_locked_until = NULL,
             last_login = NOW()
         WHERE id = $1`,
        [user.id]
      );

      // Generate JWT
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Set cookie
      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
      });

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          isVerified: user.is_verified
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Login failed. Please try again.'
      });
    }
  }
);

// ============================================
// LOGOUT
// ============================================
router.post('/logout', authenticateToken, (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true, message: 'Logged out successfully' });
});

// ============================================
// GET CURRENT USER
// ============================================
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, is_verified, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user data'
    });
  }
});

// ============================================
// FORGOT PASSWORD
// ============================================
router.post('/forgot-password',
  resetLimiter,
  [body('email').isEmail().normalizeEmail()],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Invalid email address'
        });
      }

      const { email } = req.body;

      // Find user (but don't reveal if exists)
      const result = await pool.query(
        'SELECT id, email FROM users WHERE email = $1',
        [email]
      );

      // Always return success to prevent email enumeration
      if (result.rows.length === 0) {
        return res.json({
          success: true,
          message: 'If that email exists, a reset link has been sent. 💕'
        });
      }

      const user = result.rows[0];

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      // Save token
      await pool.query(
        `UPDATE users 
         SET reset_token = $1, 
             reset_token_expiry = $2 
         WHERE id = $3`,
        [resetToken, resetExpiry, user.id]
      );

      // Send email
      const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
      await sendPasswordResetEmail(email, resetLink);

      res.json({
        success: true,
        message: 'If that email exists, a reset link has been sent. 💕'
      });

    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to process request'
      });
    }
  }
);

// ============================================
// RESET PASSWORD
// ============================================
router.post('/reset-password/:token',
  [
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must be 8+ chars with uppercase, lowercase, and number')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: errors.array()[0].msg
        });
      }

      const { token } = req.params;
      const { password } = req.body;

      // Find user with token
      const result = await pool.query(
        `SELECT id, email, reset_token_expiry 
         FROM users 
         WHERE reset_token = $1`,
        [token]
      );

      if (result.rows.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset link'
        });
      }

      const user = result.rows[0];

      // Check expiry
      if (new Date() > new Date(user.reset_token_expiry)) {
        return res.status(400).json({
          success: false,
          message: 'Reset link has expired. Please request a new one.'
        });
      }

      // Hash new password
      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      // Update password and clear token
      await pool.query(
        `UPDATE users 
         SET password_hash = $1, 
             reset_token = NULL, 
             reset_token_expiry = NULL 
         WHERE id = $2`,
        [passwordHash, user.id]
      );

      res.json({
        success: true,
        message: 'Password reset successfully! You can now log in. 💕'
      });

    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to reset password'
      });
    }
  }
);

module.exports = router;
