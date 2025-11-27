-- =====================================================
-- Cybersecurity Project - Database Initialization
-- =====================================================
-- This script creates the database and all required tables
-- for the authentication system
-- =====================================================

-- Create database
CREATE DATABASE IF NOT EXISTS cybersecurity_db;

-- Use the database
USE cybersecurity_db;

-- =====================================================
-- USERS TABLE
-- =====================================================
-- Stores user account information
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL COMMENT 'Bcrypt hashed password',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Account active status',
    role ENUM('user', 'admin') DEFAULT 'user' COMMENT 'User role for permissions',
    
    -- Indexes for performance
    INDEX idx_email (email),
    INDEX idx_is_active (is_active),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- SESSIONS TABLE
-- =====================================================
-- Stores active user sessions and JWT tokens
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(500) NOT NULL COMMENT 'JWT token',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NULL COMMENT 'IP address of session',
    user_agent TEXT NULL COMMENT 'Browser/device information',
    
    -- Foreign key constraint
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    -- Indexes for performance
    INDEX idx_token (token(255)),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- PASSWORD RESETS TABLE
-- =====================================================
-- Stores password reset tokens
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reset_token VARCHAR(255) NOT NULL COMMENT 'Unique reset token',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used BOOLEAN DEFAULT FALSE COMMENT 'Whether token has been used',
    used_at TIMESTAMP NULL DEFAULT NULL,
    
    -- Foreign key constraint
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    -- Indexes for performance
    INDEX idx_reset_token (reset_token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- AUTH LOGS TABLE
-- =====================================================
-- Audit log for authentication events
CREATE TABLE IF NOT EXISTS auth_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL COMMENT 'NULL for failed login attempts',
    email VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL COMMENT 'login, logout, signup, failed_login, password_reset',
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT NULL COMMENT 'Error details for failed attempts',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign key constraint (SET NULL on delete to keep audit trail)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    -- Indexes for performance
    INDEX idx_user_id (user_id),
    INDEX idx_email (email),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at),
    INDEX idx_success (success)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- OPTIONAL: Create a test admin user
-- =====================================================
-- Password: admin123 (hashed with bcrypt)
-- Note: This is for development only. Remove in production!
INSERT INTO users (name, email, password, role) 
VALUES (
    'Admin User', 
    'admin@cybersecurity.com', 
    '$2a$10$YourBcryptHashHere',  -- Replace with actual bcrypt hash
    'admin'
) ON DUPLICATE KEY UPDATE email=email;

-- =====================================================
-- CLEANUP PROCEDURES
-- =====================================================

-- Procedure to clean up expired sessions
DELIMITER $$
CREATE PROCEDURE IF NOT EXISTS cleanup_expired_sessions()
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    SELECT ROW_COUNT() AS deleted_sessions;
END$$
DELIMITER ;

-- Procedure to clean up expired password reset tokens
DELIMITER $$
CREATE PROCEDURE IF NOT EXISTS cleanup_expired_resets()
BEGIN
    DELETE FROM password_resets WHERE expires_at < NOW() OR used = TRUE;
    SELECT ROW_COUNT() AS deleted_resets;
END$$
DELIMITER ;

-- Procedure to clean up old auth logs (older than 90 days)
DELIMITER $$
CREATE PROCEDURE IF NOT EXISTS cleanup_old_auth_logs()
BEGIN
    DELETE FROM auth_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
    SELECT ROW_COUNT() AS deleted_logs;
END$$
DELIMITER ;

-- =====================================================
-- EVENTS (Automatic Cleanup)
-- =====================================================
-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- Event to clean up expired sessions daily
CREATE EVENT IF NOT EXISTS daily_session_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL cleanup_expired_sessions();

-- Event to clean up expired password resets daily
CREATE EVENT IF NOT EXISTS daily_reset_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL cleanup_expired_resets();

-- Event to clean up old auth logs weekly
CREATE EVENT IF NOT EXISTS weekly_log_cleanup
ON SCHEDULE EVERY 1 WEEK
STARTS CURRENT_TIMESTAMP
DO CALL cleanup_old_auth_logs();

-- =====================================================
-- VIEWS
-- =====================================================

-- View for active users
CREATE OR REPLACE VIEW active_users AS
SELECT 
    id,
    name,
    email,
    role,
    created_at,
    last_login
FROM users
WHERE is_active = TRUE;

-- View for recent login activity
CREATE OR REPLACE VIEW recent_login_activity AS
SELECT 
    u.id,
    u.name,
    u.email,
    al.action,
    al.ip_address,
    al.success,
    al.created_at
FROM auth_logs al
LEFT JOIN users u ON al.user_id = u.id
WHERE al.action IN ('login', 'failed_login')
ORDER BY al.created_at DESC
LIMIT 100;

-- =====================================================
-- VERIFICATION QUERIES
-- =====================================================

-- Show all tables
SELECT 'Tables created:' AS status;
SHOW TABLES;

-- Show table structures
SELECT 'Users table structure:' AS status;
DESCRIBE users;

SELECT 'Sessions table structure:' AS status;
DESCRIBE sessions;

SELECT 'Password resets table structure:' AS status;
DESCRIBE password_resets;

SELECT 'Auth logs table structure:' AS status;
DESCRIBE auth_logs;

-- Show procedures
SELECT 'Stored procedures:' AS status;
SHOW PROCEDURE STATUS WHERE Db = 'cybersecurity_db';

-- Show events
SELECT 'Scheduled events:' AS status;
SHOW EVENTS FROM cybersecurity_db;

-- =====================================================
-- SUCCESS MESSAGE
-- =====================================================
SELECT '✅ Database setup completed successfully!' AS status;
SELECT 'Database: cybersecurity_db' AS info;
SELECT 'Tables: users, sessions, password_resets, auth_logs' AS info;
SELECT 'Ready for authentication implementation!' AS info;
