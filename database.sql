-- ========================================
-- FRESHMARKET AUTHENTICATION DATABASE SCHEMA
-- Optimized for security, performance, and scalability
-- ========================================

-- Create database
CREATE DATABASE IF NOT EXISTS grocery_deliver 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE grocery_deliver;

-- ========================================
-- USERS TABLE - Enhanced with security features
-- ========================================

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Basic Information
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('buyer', 'seller', 'admin') NOT NULL,
    
    -- Optional Information
    gender ENUM('male', 'female', 'other') NULL,
    date_of_birth DATE NULL,
    profile_image VARCHAR(255) NULL,
    
    -- Location Information (for sellers)
    address TEXT NULL,
    latitude DECIMAL(10, 8) NULL,
    longitude DECIMAL(11, 8) NULL,
    city VARCHAR(100) NULL,
    state VARCHAR(100) NULL,
    country VARCHAR(100) DEFAULT 'India',
    pincode VARCHAR(10) NULL,
    
    -- Verification & Status
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    suspension_reason TEXT NULL,
    email_verified_at TIMESTAMP NULL,
    phone_verified_at TIMESTAMP NULL,
    
    -- Security & Activity Tracking
    password_changed_at TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    login_count INT UNSIGNED DEFAULT 0,
    failed_login_attempts INT UNSIGNED DEFAULT 0,
    locked_until TIMESTAMP NULL,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    
    PRIMARY KEY (id),
    
    -- Unique constraints for role-specific uniqueness
    UNIQUE KEY unique_email_role (email, role),
    UNIQUE KEY unique_phone_role (phone, role),
    
    -- Indexes for performance
    INDEX idx_email (email),
    INDEX idx_phone (phone),
    INDEX idx_role (role),
    INDEX idx_verification (is_verified, is_active),
    INDEX idx_location (latitude, longitude),
    INDEX idx_created_at (created_at),
    INDEX idx_last_login (last_login),
    
    -- Full-text search index for name and address
    FULLTEXT KEY ft_search (name, address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- USER SESSIONS TABLE - Enhanced security
-- ========================================

CREATE TABLE user_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    
    -- Token Information
    token_hash VARCHAR(64) NOT NULL COMMENT 'SHA256 hash of access token',
    refresh_token_hash VARCHAR(64) NOT NULL COMMENT 'SHA256 hash of refresh token',
    
    -- Session Metadata
    ip_address VARCHAR(45) NULL COMMENT 'IPv4 or IPv6 address',
    user_agent TEXT NULL,
    device_type VARCHAR(50) NULL,
    browser VARCHAR(100) NULL,
    os VARCHAR(100) NULL,
    location_country VARCHAR(2) NULL,
    location_city VARCHAR(100) NULL,
    
    -- Session Timing
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Security Flags
    is_suspicious BOOLEAN DEFAULT FALSE,
    logout_reason ENUM('user', 'timeout', 'security', 'admin') NULL,
    
    PRIMARY KEY (id),
    
    -- Foreign key constraint
    CONSTRAINT fk_sessions_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) 
        ON DELETE CASCADE ON UPDATE CASCADE,
    
    -- Indexes
    INDEX idx_user_id (user_id),
    INDEX idx_token_hash (token_hash),
    INDEX idx_refresh_token_hash (refresh_token_hash),
    INDEX idx_expires_at (expires_at),
    INDEX idx_last_activity (last_activity),
    INDEX idx_ip_address (ip_address),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- OTP VERIFICATIONS TABLE - Enhanced security
-- ========================================

CREATE TABLE otp_verifications (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- OTP Information
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    type ENUM('registration', 'login', 'password_reset', 'email_verification', 'phone_verification') NOT NULL,
    
    -- Security & Timing
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP NULL,
    attempts INT UNSIGNED DEFAULT 0,
    max_attempts INT UNSIGNED DEFAULT 3,
    
    -- Metadata
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    
    -- Indexes
    INDEX idx_email_type (email, type),
    INDEX idx_otp_type (otp, type),
    INDEX idx_expires_at (expires_at),
    INDEX idx_created_at (created_at),
    INDEX idx_is_used (is_used)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- TEMPORARY REGISTRATIONS TABLE
-- ========================================

CREATE TABLE temp_registrations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Registration Data
    email VARCHAR(255) NOT NULL,
    role ENUM('buyer', 'seller') NOT NULL,
    user_data JSON NOT NULL COMMENT 'Encrypted user registration data',
    
    -- Security & Timing
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45) NULL,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    
    -- Unique constraint to prevent duplicate registrations
    UNIQUE KEY unique_email_role (email, role),
    
    -- Indexes
    INDEX idx_expires_at (expires_at),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- AUDIT LOGS TABLE - Security monitoring
-- ========================================

CREATE TABLE audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Event Information
    user_id BIGINT UNSIGNED NULL,
    event_type ENUM(
        'user_login', 'user_logout', 'user_register', 'password_change', 
        'otp_send', 'otp_verify', 'profile_update', 'session_create',
        'session_expire', 'suspicious_activity', 'account_lock', 'account_unlock'
    ) NOT NULL,
    
    -- Event Details
    description TEXT NULL,
    old_values JSON NULL,
    new_values JSON NULL,
    
    -- Context Information
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    session_id BIGINT UNSIGNED NULL,
    
    -- Risk Assessment
    risk_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    
    -- Foreign key constraints
    CONSTRAINT fk_audit_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) 
        ON DELETE SET NULL ON UPDATE CASCADE,
    
    CONSTRAINT fk_audit_session_id 
        FOREIGN KEY (session_id) REFERENCES user_sessions(id) 
        ON DELETE SET NULL ON UPDATE CASCADE,
    
    -- Indexes
    INDEX idx_user_id (user_id),
    INDEX idx_event_type (event_type),
    INDEX idx_created_at (created_at),
    INDEX idx_risk_level (risk_level),
    INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- PASSWORD HISTORY TABLE - Prevent reuse
-- ========================================

CREATE TABLE password_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    
    -- Foreign key constraint
    CONSTRAINT fk_password_history_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) 
        ON DELETE CASCADE ON UPDATE CASCADE,
    
    -- Indexes
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- SECURITY SETTINGS TABLE - User preferences
-- ========================================

CREATE TABLE user_security_settings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    
    -- Two-Factor Authentication
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(32) NULL,
    backup_codes JSON NULL,
    
    -- Security Preferences
    login_notifications BOOLEAN DEFAULT TRUE,
    suspicious_activity_alerts BOOLEAN DEFAULT TRUE,
    session_timeout_minutes INT UNSIGNED DEFAULT 1440, -- 24 hours
    
    -- Recovery Options
    recovery_email VARCHAR(255) NULL,
    recovery_phone VARCHAR(20) NULL,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    
    -- Foreign key constraint
    CONSTRAINT fk_security_settings_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) 
        ON DELETE CASCADE ON UPDATE CASCADE,
    
    -- Unique constraint
    UNIQUE KEY unique_user_security (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- RATE LIMITING TABLE - API protection
-- ========================================

CREATE TABLE rate_limits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Identifier (IP, user ID, or combination)
    identifier VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    
    -- Rate limiting data
    requests_count INT UNSIGNED DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NULL,
    
    -- Metadata
    last_request_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (id),
    
    -- Unique constraint for rate limiting logic
    UNIQUE KEY unique_identifier_action (identifier, action),
    
    -- Indexes
    INDEX idx_window_start (window_start),
    INDEX idx_blocked_until (blocked_until),
    INDEX idx_last_request_at (last_request_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ========================================
-- TRIGGERS FOR AUDIT LOGGING
-- ========================================

DELIMITER $

-- Trigger for user login logging
CREATE TRIGGER tr_user_login_audit
    AFTER UPDATE ON users
    FOR EACH ROW
BEGIN
    IF NEW.last_login != OLD.last_login THEN
        INSERT INTO audit_logs (user_id, event_type, description, new_values)
        VALUES (NEW.id, 'user_login', 'User logged in', JSON_OBJECT('last_login', NEW.last_login));
    END IF;
END$

-- Trigger for password change logging
CREATE TRIGGER tr_password_change_audit
    AFTER UPDATE ON users
    FOR EACH ROW
BEGIN
    IF NEW.password != OLD.password THEN
        INSERT INTO audit_logs (user_id, event_type, description)
        VALUES (NEW.id, 'password_change', 'User changed password');
        
        -- Store old password in history
        INSERT INTO password_history (user_id, password_hash)
        VALUES (NEW.id, OLD.password);
    END IF;
END$

-- Trigger for user registration audit
CREATE TRIGGER tr_user_registration_audit
    AFTER INSERT ON users
    FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (user_id, event_type, description, new_values)
    VALUES (NEW.id, 'user_register', 'User registered', JSON_OBJECT('role', NEW.role, 'email', NEW.email));
END$

DELIMITER ;

-- ========================================
-- STORED PROCEDURES FOR COMMON OPERATIONS
-- ========================================

DELIMITER $

-- Procedure to clean expired sessions
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    
    DELETE FROM user_sessions 
    WHERE expires_at < UTC_TIMESTAMP() 
       OR last_activity < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY);
    
    SET deleted_count = ROW_COUNT();
    
    INSERT INTO audit_logs (event_type, description, new_values)
    VALUES ('session_expire', 'Cleaned expired sessions', JSON_OBJECT('deleted_count', deleted_count));
END$

-- Procedure to clean expired OTPs
CREATE PROCEDURE CleanExpiredOTPs()
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    
    DELETE FROM otp_verifications 
    WHERE expires_at < UTC_TIMESTAMP() 
       OR created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY);
    
    SET deleted_count = ROW_COUNT();
    
    INSERT INTO audit_logs (event_type, description, new_values)
    VALUES ('otp_cleanup', 'Cleaned expired OTPs', JSON_OBJECT('deleted_count', deleted_count));
END$

-- Procedure to clean expired temp registrations
CREATE PROCEDURE CleanExpiredTempRegistrations()
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    
    DELETE FROM temp_registrations 
    WHERE expires_at < UTC_TIMESTAMP();
    
    SET deleted_count = ROW_COUNT();
    
    INSERT INTO audit_logs (event_type, description, new_values)
    VALUES ('temp_reg_cleanup', 'Cleaned expired temp registrations', JSON_OBJECT('deleted_count', deleted_count));
END$

-- Procedure to lock user account after failed attempts
CREATE PROCEDURE LockUserAccount(IN p_user_id BIGINT UNSIGNED, IN p_lock_duration_minutes INT)
BEGIN
    UPDATE users 
    SET failed_login_attempts = failed_login_attempts + 1,
        locked_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL p_lock_duration_minutes MINUTE)
    WHERE id = p_user_id;
    
    INSERT INTO audit_logs (user_id, event_type, description, new_values)
    VALUES (p_user_id, 'account_lock', 'Account locked due to failed login attempts', 
            JSON_OBJECT('lock_duration_minutes', p_lock_duration_minutes));
END$

-- Procedure to get user session statistics
CREATE PROCEDURE GetUserSessionStats(IN p_user_id BIGINT UNSIGNED)
BEGIN
    SELECT 
        COUNT(*) as total_sessions,
        COUNT(CASE WHEN expires_at > UTC_TIMESTAMP() THEN 1 END) as active_sessions,
        MAX(last_activity) as last_activity,
        MIN(created_at) as first_session,
        COUNT(DISTINCT ip_address) as unique_ips,
        COUNT(DISTINCT browser) as unique_browsers
    FROM user_sessions 
    WHERE user_id = p_user_id;
END$

DELIMITER ;

-- ========================================
-- EVENTS FOR AUTOMATIC CLEANUP
-- ========================================

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- Event to clean expired sessions daily
CREATE EVENT IF NOT EXISTS ev_clean_expired_sessions
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
  CALL CleanExpiredSessions();

-- Event to clean expired OTPs every hour
CREATE EVENT IF NOT EXISTS ev_clean_expired_otps
ON SCHEDULE EVERY 1 HOUR
STARTS CURRENT_TIMESTAMP
DO
  CALL CleanExpiredOTPs();

-- Event to clean expired temp registrations every 30 minutes
CREATE EVENT IF NOT EXISTS ev_clean_expired_temp_registrations
ON SCHEDULE EVERY 30 MINUTE
STARTS CURRENT_TIMESTAMP
DO
  CALL CleanExpiredTempRegistrations();

-- ========================================
-- VIEWS FOR COMMON QUERIES
-- ========================================

-- View for active users with security info
CREATE VIEW v_active_users AS
SELECT 
    u.id,
    u.name,
    u.email,
    u.role,
    u.is_verified,
    u.last_login,
    u.login_count,
    u.failed_login_attempts,
    u.locked_until,
    u.created_at,
    uss.two_factor_enabled,
    uss.login_notifications,
    COUNT(DISTINCT us.id) as active_sessions
FROM users u
LEFT JOIN user_security_settings uss ON u.id = uss.user_id
LEFT JOIN user_sessions us ON u.id = us.user_id AND us.expires_at > UTC_TIMESTAMP()
WHERE u.is_active = TRUE AND u.deleted_at IS NULL
GROUP BY u.id;

-- View for recent security events
CREATE VIEW v_recent_security_events AS
SELECT 
    al.id,
    al.user_id,
    u.name as user_name,
    u.email as user_email,
    al.event_type,
    al.description,
    al.risk_level,
    al.ip_address,
    al.created_at
FROM audit_logs al
LEFT JOIN users u ON al.user_id = u.id
WHERE al.created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
ORDER BY al.created_at DESC;

-- ========================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ========================================

-- Composite indexes for common query patterns
CREATE INDEX idx_users_role_verified_active ON users (role, is_verified, is_active);
CREATE INDEX idx_users_email_role_active ON users (email, role, is_active);
CREATE INDEX idx_sessions_user_expires ON user_sessions (user_id, expires_at);
CREATE INDEX idx_otps_email_type_expires ON otp_verifications (email, type, expires_at);
CREATE INDEX idx_audit_user_event_created ON audit_logs (user_id, event_type, created_at);

-- ========================================
-- INITIAL DATA AND CONFIGURATION
-- ========================================

-- Insert default admin user (password should be changed immediately)
INSERT INTO users (
    name, email, phone, password, role, 
    is_verified, is_active, email_verified_at
) VALUES (
    'System Administrator',
    'admin@freshmarket.com',
    '9999999999',
    '$2b$12$LQv3c1yqBwVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNnKmTLRJO9CO', -- 'admin123' - CHANGE THIS!
    'admin',
    TRUE,
    TRUE,
    UTC_TIMESTAMP()
);

-- Insert default security settings for admin
INSERT INTO user_security_settings (user_id, two_factor_enabled, login_notifications)
VALUES (LAST_INSERT_ID(), FALSE, TRUE);

-- ========================================
-- DATABASE MAINTENANCE COMMANDS
-- ========================================

-- Optimize tables for better performance
OPTIMIZE TABLE users;
OPTIMIZE TABLE user_sessions;
OPTIMIZE TABLE otp_verifications;
OPTIMIZE TABLE audit_logs;

-- Analyze tables for query optimization
ANALYZE TABLE users;
ANALYZE TABLE user_sessions;
ANALYZE TABLE otp_verifications;
ANALYZE TABLE audit_logs;

-- ========================================
-- SECURITY RECOMMENDATIONS
-- ========================================

/*
1. ENVIRONMENT VARIABLES:
   - Set strong passwords for database users
   - Use SSL/TLS for database connections
   - Implement proper firewall rules

2. BACKUP STRATEGY:
   - Daily full backups
   - Point-in-time recovery enabled
   - Encrypted backup storage

3. MONITORING:
   - Set up alerts for suspicious activities
   - Monitor failed login attempts
   - Track unusual session patterns

4. REGULAR MAINTENANCE:
   - Update statistics regularly
   - Monitor disk space usage
   - Review and archive old audit logs

5. ACCESS CONTROL:
   - Use principle of least privilege
   - Implement role-based database access
   - Regular access reviews
*/

-- Performance indexes for common queries
CREATE INDEX idx_users_email_role_active ON users(email, role, is_active);
CREATE INDEX idx_sessions_active ON user_sessions(user_id, expires_at);


-- Cleanup stored procedure
DELIMITER //
CREATE PROCEDURE cleanup_expired_data()
BEGIN
  DELETE FROM user_sessions WHERE expires_at < UTC_TIMESTAMP();
  DELETE FROM otp_verifications WHERE expires_at < UTC_TIMESTAMP();
  DELETE FROM temp_registrations WHERE expires_at < UTC_TIMESTAMP();
END //
DELIMITER ;
