// middleware/auth.js - Authentication Middleware
const jwt = require('jsonwebtoken');
const { pool } = require('../server');

const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Middleware to authenticate JWT token from cookie
 * Validates token and attaches user info to req.user
 */
const authenticateToken = async (req, res, next) => {
  try {
    // Get token from cookie
    const token = req.cookies.auth_token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check if user still exists and is verified
    const result = await pool.query(
      `SELECT id, email, is_verified, account_locked_until 
       FROM users 
       WHERE id = $1`,
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = result.rows[0];

    // Check if verified
    if (!user.is_verified) {
      return res.status(403).json({
        success: false,
        message: 'Email not verified'
      });
    }

    // Check if account is locked
    if (user.account_locked_until && new Date() < new Date(user.account_locked_until)) {
      return res.status(423).json({
        success: false,
        message: 'Account temporarily locked'
      });
    }

    // Attach user to request
    req.user = {
      userId: user.id,
      email: user.email
    };

    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please log in again.'
      });
    }

    console.error('Auth middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
};

/**
 * Optional authentication - doesn't fail if no token
 * Used for routes that work differently for authenticated users
 */
const optionalAuthentication = async (req, res, next) => {
  try {
    const token = req.cookies.auth_token;

    if (!token) {
      req.user = null;
      return next();
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      'SELECT id, email FROM users WHERE id = $1 AND is_verified = true',
      [decoded.userId]
    );

    if (result.rows.length > 0) {
      req.user = {
        userId: result.rows[0].id,
        email: result.rows[0].email
      };
    } else {
      req.user = null;
    }

    next();

  } catch (error) {
    req.user = null;
    next();
  }
};

module.exports = {
  authenticateToken,
  optionalAuthentication
};
