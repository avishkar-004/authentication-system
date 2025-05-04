const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ========================================
// SECTION 1: SECURITY & MIDDLEWARE
// ========================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Enhanced Rate Limiting
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { success: false, message },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message,
      retryAfter: Math.round(windowMs / 1000)
    });
  }
});

app.use('/api/auth/login', createRateLimit(15 * 60 * 1000, 5, 'Too many login attempts'));
app.use('/api/auth/register', createRateLimit(15 * 60 * 1000, 3, 'Too many registration attempts'));
app.use('/api/auth/send-password-reset-otp', createRateLimit(5 * 60 * 1000, 3, 'Too many OTP requests'));
app.use('/api/auth/verify-otp', createRateLimit(15 * 60 * 1000, 10, 'Too many OTP verification attempts'));

// ========================================
// SECTION 2: DATABASE CONNECTION
// ========================================

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME || 'grocery_deliver',
  timezone: '+00:00',
  charset: 'utf8mb4',
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

let dbPool;

async function initializeDatabase() {
  try {
    dbPool = mysql.createPool({
      ...dbConfig,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      reconnect: true,
      acquireTimeout: 60000,
      timeout: 60000
    });

    // Test connection
    const connection = await dbPool.getConnection();
    await connection.ping();
    connection.release();
    
    console.log('✅ Database pool initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    process.exit(1);
  }
}

initializeDatabase();

// ========================================
// SECTION 3: UTILITY FUNCTIONS
// ========================================

// Response formatter
const formatResponse = (success, message, data = null, error = null) => ({
  success,
  message,
  data,
  error,
  timestamp: new Date().toISOString()
});

// Enhanced password hashing
async function hashPassword(password) {
  try {
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    console.error('Password hashing error:', error);
    throw new Error('Password hashing failed');
  }
}

async function verifyPassword(inputPassword, hashedPassword) {
  try {
    return await bcrypt.compare(inputPassword, hashedPassword);
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
}

// Enhanced OTP generation
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// Email configuration with retry logic
const transporter = nodemailer.createTransporter({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

async function sendEmail(to, subject, html, retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await transporter.sendMail({
        from: `"FreshMarket" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html
      });
      return true;
    } catch (error) {
      console.error(`Email send attempt ${attempt} failed:`, error.message);
      if (attempt === retries) return false;
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  return false;
}

// Enhanced JWT functions
function generateAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    issuer: 'freshmarket',
    audience: 'freshmarket-users'
  });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: 'freshmarket',
    audience: 'freshmarket-users'
  });
}

function verifyToken(token, secret = process.env.JWT_SECRET) {
  return jwt.verify(token, secret, {
    issuer: 'freshmarket',
    audience: 'freshmarket-users'
  });
}

// ========================================
// SECTION 4: MIDDLEWARE
// ========================================

// Enhanced authentication middleware
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json(formatResponse(false, 'Access token required'));
    }

    const decoded = verifyToken(token);
    
    // Verify session exists and is valid
    const [sessions] = await dbPool.execute(
      'SELECT s.*, u.* FROM user_sessions s JOIN users u ON s.user_id = u.id WHERE s.user_id = ? AND s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP() AND u.is_active = TRUE AND u.is_suspended = FALSE',
      [decoded.userId, crypto.createHash('sha256').update(token).digest('hex')]
    );

    if (sessions.length === 0) {
      return res.status(401).json(formatResponse(false, 'Invalid or expired session'));
    }

    // Update last activity
    await dbPool.execute(
      'UPDATE user_sessions SET last_activity = UTC_TIMESTAMP() WHERE id = ?',
      [sessions[0].id]
    );

    req.user = sessions[0];
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    return res.status(401).json(formatResponse(false, 'Invalid token'));
  }
}

// Role authorization
const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json(formatResponse(false, 'Insufficient permissions'));
  }
  next();
};

// Enhanced validation error handler
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => `${error.path}: ${error.msg}`);
    return res.status(422).json(formatResponse(false, 'Validation failed', null, errorMessages));
  }
  next();
}

// ========================================
// SECTION 5: AUTHENTICATION ROUTES
// ========================================

// Login endpoint
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('role').isIn(['seller', 'buyer', 'admin']).withMessage('Valid role required')
], handleValidationErrors, async (req, res) => {
  let connection;
  try {
    const { email, password, role } = req.body;

    connection = await dbPool.getConnection();
    await connection.beginTransaction();

    // Find user with email and role
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE email = ? AND role = ? AND is_active = TRUE',
      [email, role]
    );

    if (users.length === 0) {
      await connection.rollback();
      return res.status(401).json(formatResponse(false, 'Invalid credentials'));
    }

    const user = users[0];

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      await connection.rollback();
      return res.status(401).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if user is suspended
    if (user.is_suspended) {
      await connection.rollback();
      return res.status(403).json(formatResponse(false, 'Account suspended. Contact support.'));
    }

    // Generate tokens
    const tokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role
    };

    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);

    // Create session
    const sessionExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    const tokenHash = crypto.createHash('sha256').update(accessToken).digest('hex');

    await connection.execute(
      'INSERT INTO user_sessions (user_id, token_hash, refresh_token_hash, expires_at, ip_address, user_agent, last_activity) VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())',
      [
        user.id,
        tokenHash,
        crypto.createHash('sha256').update(refreshToken).digest('hex'),
        sessionExpiry,
        req.ip || 'unknown',
        req.headers['user-agent'] || 'unknown'
      ]
    );

    // Update last login
    await connection.execute(
      'UPDATE users SET last_login = UTC_TIMESTAMP(), login_count = login_count + 1 WHERE id = ?',
      [user.id]
    );

    await connection.commit();

    // Set secure HTTP-only cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    };

    res.cookie('refreshToken', refreshToken, cookieOptions);

    res.json(formatResponse(true, 'Login successful', {
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        is_verified: user.is_verified
      }
    }));

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Login error:', error);
    res.status(500).json(formatResponse(false, 'Login failed', null, error.message));
  } finally {
    if (connection) connection.release();
  }
});

// Register endpoint
app.post('/api/auth/register', [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('phone').matches(/^\d{10}$/).withMessage('Valid 10-digit phone number required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['buyer', 'seller']).withMessage('Role must be buyer or seller'),
  body('gender').optional().isIn(['male', 'female', 'other']),
  body('address').if(body('role').equals('seller')).notEmpty().withMessage('Address required for sellers'),
  body('latitude').if(body('role').equals('seller')).isFloat().withMessage('Valid latitude required for sellers'),
  body('longitude').if(body('role').equals('seller')).isFloat().withMessage('Valid longitude required for sellers')
], handleValidationErrors, async (req, res) => {
  let connection;
  try {
    const {
      name, email: rawEmail, phone, password,
      role: rawRole, gender, date_of_birth, address, latitude, longitude
    } = req.body;

    const email = rawEmail.toLowerCase().trim();
    const role = rawRole.toLowerCase().trim();

    connection = await dbPool.getConnection();
    await connection.beginTransaction();

    // Check if user already exists
    const [existingUsers] = await connection.execute(
      'SELECT id FROM users WHERE (email = ? OR phone = ?) AND role = ?',
      [email, phone, role]
    );

    if (existingUsers.length > 0) {
      await connection.rollback();
      return res.status(409).json(formatResponse(false, `User already exists with this email or phone for ${role} role`));
    }

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Clean up old OTPs for this email
    await connection.execute(
      'DELETE FROM otp_verifications WHERE email = ? AND type = ? AND created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)',
      [email, 'registration']
    );

    // Insert new OTP
    await connection.execute(
      'INSERT INTO otp_verifications (email, otp, type, expires_at) VALUES (?, ?, ?, ?)',
      [email, otp, 'registration', otpExpiry]
    );

    // Store temporary registration data
    const hashedPassword = await hashPassword(password);
    const tempUserData = {
      name,
      email,
      phone,
      password: hashedPassword,
      role,
      gender: gender || null,
      date_of_birth: date_of_birth || null,
      address: address || null,
      latitude: latitude || null,
      longitude: longitude || null
    };

    // Store in database temporarily
    await connection.execute(
      'INSERT INTO temp_registrations (email, role, user_data, expires_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE user_data = VALUES(user_data), expires_at = VALUES(expires_at)',
      [email, role, JSON.stringify(tempUserData), new Date(Date.now() + 30 * 60 * 1000)]
    );

    await connection.commit();

    // Send OTP email
    const emailSent = await sendEmail(
      email,
      'Registration OTP - FreshMarket',
      generateRegistrationEmailTemplate(otp, role, name)
    );

    if (!emailSent) {
      return res.status(500).json(formatResponse(false, 'Failed to send OTP email'));
    }

    res.json(formatResponse(true, `OTP sent successfully for ${role} registration`));

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Registration error:', error);
    res.status(500).json(formatResponse(false, 'Registration failed', null, error.message));
  } finally {
    if (connection) connection.release();
  }
});

// OTP Verification endpoint
app.post('/api/auth/verify-otp', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('otp').isLength({ min: 6, max: 6 }).isNumeric().withMessage('6-digit OTP required'),
  body('type').isIn(['registration', 'password_reset']).withMessage('Valid type required'),
  body('role').if(body('type').equals('registration')).isIn(['buyer', 'seller']).withMessage('Role required for registration')
], handleValidationErrors, async (req, res) => {
  let connection;
  try {
    const { email, otp, type, role } = req.body;

    connection = await dbPool.getConnection();
    await connection.beginTransaction();

    // Verify OTP
    const [otpRecords] = await connection.execute(
      'SELECT * FROM otp_verifications WHERE email = ? AND otp = ? AND type = ? AND expires_at > UTC_TIMESTAMP() AND is_used = FALSE ORDER BY created_at DESC LIMIT 1',
      [email, otp, type]
    );

    if (otpRecords.length === 0) {
      await connection.rollback();
      return res.status(400).json(formatResponse(false, 'Invalid or expired OTP'));
    }

    // Mark OTP as used
    await connection.execute(
      'UPDATE otp_verifications SET is_used = TRUE WHERE id = ?',
      [otpRecords[0].id]
    );

    if (type === 'registration') {
      // Get temporary registration data
      const [tempData] = await connection.execute(
        'SELECT user_data FROM temp_registrations WHERE email = ? AND role = ? AND expires_at > UTC_TIMESTAMP()',
        [email, role]
      );

      if (tempData.length === 0) {
        await connection.rollback();
        return res.status(400).json(formatResponse(false, 'Registration session expired. Please register again.'));
      }

      const userData = JSON.parse(tempData[0].user_data);

      // Create user account
      const [result] = await connection.execute(
        `INSERT INTO users 
         (name, email, phone, password, role, gender, date_of_birth, address, latitude, longitude, is_verified, email_verified_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, UTC_TIMESTAMP())`,
        [
          userData.name,
          userData.email,
          userData.phone,
          userData.password,
          userData.role,
          userData.gender,
          userData.date_of_birth,
          userData.address,
          userData.latitude,
          userData.longitude
        ]
      );

      // Clean up temporary data
      await connection.execute(
        'DELETE FROM temp_registrations WHERE email = ? AND role = ?',
        [email, role]
      );

      await connection.commit();

      res.status(201).json(formatResponse(true, `${role} registration completed successfully`, {
        user: {
          id: result.insertId,
          name: userData.name,
          email: userData.email,
          role: userData.role,
          is_verified: true
        }
      }));
    } else {
      await connection.commit();
      res.json(formatResponse(true, 'OTP verified successfully'));
    }

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('OTP verification error:', error);
    res.status(500).json(formatResponse(false, 'OTP verification failed', null, error.message));
  } finally {
    if (connection) connection.release();
  }
});

// Password reset OTP
app.post('/api/auth/send-password-reset-otp', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('role').isIn(['buyer', 'seller', 'admin']).withMessage('Valid role required')
], handleValidationErrors, async (req, res) => {
  let connection;
  try {
    const { email, role } = req.body;

    connection = await dbPool.getConnection();
    await connection.beginTransaction();

    // Check if user exists
    const [users] = await connection.execute(
      'SELECT id, name FROM users WHERE email = ? AND role = ? AND is_active = TRUE',
      [email, role]
    );

    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json(formatResponse(false, `No ${role} account found for this email`));
    }

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    // Clean up old OTPs
    await connection.execute(
      'DELETE FROM otp_verifications WHERE email = ? AND type = ? AND created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)',
      [email, 'password_reset']
    );

    // Insert new OTP
    await connection.execute(
      'INSERT INTO otp_verifications (email, otp, type, expires_at) VALUES (?, ?, ?, ?)',
      [email, otp, 'password_reset', otpExpiry]
    );

    await connection.commit();

    // Send OTP email
    const emailSent = await sendEmail(
      email,
      'Password Reset OTP - FreshMarket',
      generatePasswordResetEmailTemplate(otp, role, users[0].name)
    );

    if (!emailSent) {
      return res.status(500).json(formatResponse(false, 'Failed to send OTP email'));
    }

    res.json(formatResponse(true, `Password reset OTP sent to your email for ${role} account`));

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Send password reset OTP error:', error);
    res.status(500).json(formatResponse(false, 'Failed to send password reset OTP', null, error.message));
  } finally {
    if (connection) connection.release();
  }
});

// Reset password
app.post('/api/auth/reset-password', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('otp').isLength({ min: 6, max: 6 }).isNumeric().withMessage('6-digit OTP required'),
  body('new_password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['buyer', 'seller', 'admin']).withMessage('Valid role required')
], handleValidationErrors, async (req, res) => {
  let connection;
  try {
    const { email, otp, new_password, role } = req.body;

    connection = await dbPool.getConnection();
    await connection.beginTransaction();

    // Verify OTP
    const [otpRecords] = await connection.execute(
      'SELECT * FROM otp_verifications WHERE email = ? AND otp = ? AND type = ? AND expires_at > UTC_TIMESTAMP() AND is_used = FALSE ORDER BY created_at DESC LIMIT 1',
      [email, otp, 'password_reset']
    );

    if (otpRecords.length === 0) {
      await connection.rollback();
      return res.status(400).json(formatResponse(false, 'Invalid or expired OTP'));
    }

    // Check if user exists
    const [users] = await connection.execute(
      'SELECT id FROM users WHERE email = ? AND role = ? AND is_active = TRUE',
      [email, role]
    );

    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json(formatResponse(false, `No ${role} account found for this email`));
    }

    // Hash new password and update
    const hashedPassword = await hashPassword(new_password);
    await connection.execute(
      'UPDATE users SET password = ?, password_changed_at = UTC_TIMESTAMP() WHERE email = ? AND role = ?',
      [hashedPassword, email, role]
    );

    // Mark OTP as used
    await connection.execute(
      'UPDATE otp_verifications SET is_used = TRUE WHERE id = ?',
      [otpRecords[0].id]
    );

    // Clear all sessions for this user
    await connection.execute(
      'DELETE FROM user_sessions WHERE user_id = ?',
      [users[0].id]
    );

    await connection.commit();

    res.json(formatResponse(true, `Password reset successfully for ${role} account`));

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Password reset error:', error);
    res.status(500).json(formatResponse(false, 'Password reset failed', null, error.message));
  } finally {
    if (connection) connection.release();
  }
});

// Refresh token endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      return res.status(401).json(formatResponse(false, 'Refresh token required'));
    }

    const decoded = verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET);
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    // Verify refresh token exists and is valid
    const [sessions] = await dbPool.execute(
      'SELECT s.*, u.* FROM user_sessions s JOIN users u ON s.user_id = u.id WHERE s.user_id = ? AND s.refresh_token_hash = ? AND s.expires_at > UTC_TIMESTAMP() AND u.is_active = TRUE AND u.is_suspended = FALSE',
      [decoded.userId, refreshTokenHash]
    );

    if (sessions.length === 0) {
      return res.status(401).json(formatResponse(false, 'Invalid refresh token'));
    }

    const user = sessions[0];

    // Generate new access token
    const newAccessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    // Update session with new access token hash
    const newTokenHash = crypto.createHash('sha256').update(newAccessToken).digest('hex');
    await dbPool.execute(
      'UPDATE user_sessions SET token_hash = ?, last_activity = UTC_TIMESTAMP() WHERE id = ?',
      [newTokenHash, sessions[0].id]
    );

    res.json(formatResponse(true, 'Token refreshed successfully', {
      accessToken: newAccessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        is_verified: user.is_verified
      }
    }));

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json(formatResponse(false, 'Token refresh failed'));
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const tokenHash = crypto.createHash('sha256').update(req.token).digest('hex');
    
    await dbPool.execute(
      'DELETE FROM user_sessions WHERE user_id = ? AND token_hash = ?',
      [req.user.id, tokenHash]
    );

    res.clearCookie('refreshToken');
    res.json(formatResponse(true, 'Logged out successfully'));

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json(formatResponse(false, 'Logout failed', null, error.message));
  }
});

// Logout from all devices
app.post('/api/auth/logout-all', authenticateToken, async (req, res) => {
  try {
    await dbPool.execute(
      'DELETE FROM user_sessions WHERE user_id = ?',
      [req.user.id]
    );

    res.clearCookie('refreshToken');
    res.json(formatResponse(true, 'Logged out from all devices successfully'));

  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json(formatResponse(false, 'Logout failed', null, error.message));
  }
});

// Get user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await dbPool.execute(
      'SELECT id, name, email, phone, role, gender, date_of_birth, address, latitude, longitude, is_verified, created_at, last_login FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    res.json(formatResponse(true, 'Profile retrieved successfully', users[0]));

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json(formatResponse(false, 'Failed to get profile', null, error.message));
  }
});

// ========================================
// EMAIL TEMPLATES
// ========================================

function generateRegistrationEmailTemplate(otp, role, name) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to FreshMarket</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background: #f8f9fa; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .otp-box { background: #e8f5e8; border: 2px dashed #28a745; padding: 25px; text-align: center; margin: 25px 0; border-radius: 8px; }
            .otp-code { font-size: 36px; font-weight: bold; color: #28a745; letter-spacing: 5px; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
            .btn { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 Welcome to FreshMarket!</h1>
                <p>Your journey to fresh groceries starts here</p>
            </div>
            <div class="content">
                <h2>Hello ${name}!</h2>
                <p>Thank you for registering as a <strong>${role}</strong> on FreshMarket. To complete your registration, please use the verification code below:</p>
                
                <div class="otp-box">
                    <div class="otp-code">${otp}</div>
                    <p style="margin: 10px 0 0; color: #666; font-size: 14px;">This code expires in 10 minutes</p>
                </div>
                
                <p>If you didn't request this registration, please ignore this email.</p>
                
                <div style="margin: 30px 0; padding: 20px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                    <strong>Security Tip:</strong> Never share your OTP with anyone. FreshMarket will never ask for your OTP via phone or email.
                </div>
            </div>
            <div class="footer">
                <p>&copy; 2024 FreshMarket. All rights reserved.</p>
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
  `;
}

function generatePasswordResetEmailTemplate(otp, role, name) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset - FreshMarket</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background: #f8f9fa; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #dc3545, #fd7e14); color: white; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .otp-box { background: #fef2f2; border: 2px dashed #dc3545; padding: 25px; text-align: center; margin: 25px 0; border-radius: 8px; }
            .otp-code { font-size: 36px; font-weight: bold; color: #dc3545; letter-spacing: 5px; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
            .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Password Reset Request</h1>
                <p>Secure your FreshMarket account</p>
            </div>
            <div class="content">
                <h2>Hello ${name}!</h2>
                <p>We received a request to reset the password for your <strong>${role}</strong> account. Use the verification code below to proceed:</p>
                
                <div class="otp-box">
                    <div class="otp-code">${otp}</div>
                    <p style="margin: 10px 0 0; color: #666; font-size: 14px;">This code expires in 10 minutes</p>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong> If you didn't request this password reset, please ignore this email and ensure your account is secure. Consider changing your password if you suspect unauthorized access.
                </div>
                
                <p>After entering this code, you'll be able to create a new password for your account.</p>
            </div>
            <div class="footer">
                <p>&copy; 2024 FreshMarket. All rights reserved.</p>
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
  `;
}

// ========================================
// ERROR HANDLING & CLEANUP
// ========================================

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json(formatResponse(false, 'Internal server error', null, process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'));
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

// Cleanup function for expired sessions and OTPs
async function cleanupExpiredData() {
  try {
    // Clean expired sessions
    await dbPool.execute('DELETE FROM user_sessions WHERE expires_at < UTC_TIMESTAMP()');
    
    // Clean expired OTPs
    await dbPool.execute('DELETE FROM otp_verifications WHERE expires_at < UTC_TIMESTAMP()');
    
    // Clean expired temp registrations
    await dbPool.execute('DELETE FROM temp_registrations WHERE expires_at < UTC_TIMESTAMP()');
    
    console.log('✅ Cleanup completed');
  } catch (error) {
    console.error('❌ Cleanup error:', error);
  }
}

// Run cleanup every hour
setInterval(cleanupExpiredData, 60 * 60 * 1000);

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await dbPool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await dbPool.end();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`🚀 Auth server running on port ${PORT}`);
});

module.exports = app;