-- database/schema.sql - Database Schema Setup
-- PostgreSQL Database Schema for CuToDo App

-- ============================================
-- USERS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS users (
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

-- Indexes for users table
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token);
CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_token);
CREATE INDEX IF NOT EXISTS idx_users_is_verified ON users(is_verified);

-- ============================================
-- TASKS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL,
    time VARCHAR(5) NOT NULL, -- HH:MM format
    duration INTEGER NOT NULL, -- minutes
    icon VARCHAR(50) NOT NULL,
    color VARCHAR(7) NOT NULL, -- hex color
    energy_cost INTEGER DEFAULT 1,
    completed BOOLEAN DEFAULT FALSE,
    date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for tasks table
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_date ON tasks(date);
CREATE INDEX IF NOT EXISTS idx_tasks_completed ON tasks(completed);
CREATE INDEX IF NOT EXISTS idx_tasks_user_date ON tasks(user_id, date);

-- ============================================
-- SESSIONS TABLE (Optional - for server-side sessions)
-- ============================================
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Indexes for sessions table
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ============================================
-- FUNCTIONS
-- ============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- TRIGGERS
-- ============================================

-- Trigger to automatically update updated_at for users
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger to automatically update updated_at for tasks
DROP TRIGGER IF EXISTS update_tasks_updated_at ON tasks;
CREATE TRIGGER update_tasks_updated_at
    BEFORE UPDATE ON tasks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- CLEANUP FUNCTIONS
-- ============================================

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired verification tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    UPDATE users
    SET verification_token = NULL,
        verification_token_expiry = NULL
    WHERE verification_token_expiry < CURRENT_TIMESTAMP
    AND is_verified = false;
    
    UPDATE users
    SET reset_token = NULL,
        reset_token_expiry = NULL
    WHERE reset_token_expiry < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- SAMPLE DATA (for development only)
-- ============================================

-- Uncomment below to insert sample data for testing
-- NOTE: Remove this in production!

/*
-- Sample user (password: TestPass123!)
INSERT INTO users (email, password_hash, is_verified) VALUES
('test@example.com', '$2b$10$YourHashedPasswordHere', true);

-- Sample tasks for the test user
INSERT INTO tasks (user_id, title, category, time, duration, icon, color, energy_cost, date) VALUES
(1, 'Morning Workout', 'Exercise', '07:00', 30, 'exercise', '#FFA8A8', 2, CURRENT_DATE),
(1, 'Breakfast', 'Food', '08:00', 20, 'food', '#7BC67E', 1, CURRENT_DATE),
(1, 'Study Session', 'School', '09:00', 60, 'school', '#F6A5C0', 3, CURRENT_DATE);
*/

-- ============================================
-- CONSTRAINTS & VALIDATIONS
-- ============================================

-- Ensure email is lowercase
CREATE OR REPLACE FUNCTION lowercase_email()
RETURNS TRIGGER AS $$
BEGIN
    NEW.email = LOWER(NEW.email);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS lowercase_email_trigger ON users;
CREATE TRIGGER lowercase_email_trigger
    BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION lowercase_email();

-- Ensure time is in valid format
ALTER TABLE tasks ADD CONSTRAINT valid_time_format 
    CHECK (time ~ '^([01]\d|2[0-3]):[0-5]\d$');

-- Ensure duration is positive
ALTER TABLE tasks ADD CONSTRAINT positive_duration 
    CHECK (duration > 0 AND duration <= 1440);

-- Ensure energy cost is valid
ALTER TABLE tasks ADD CONSTRAINT valid_energy_cost 
    CHECK (energy_cost >= 1 AND energy_cost <= 10);

-- Ensure color is valid hex
ALTER TABLE tasks ADD CONSTRAINT valid_hex_color 
    CHECK (color ~ '^#[0-9A-Fa-f]{6}$');

-- ============================================
-- PERMISSIONS (for production)
-- ============================================

-- Create application user (run these manually in production)
-- CREATE USER cutodo_app WITH PASSWORD 'your_secure_password';
-- GRANT CONNECT ON DATABASE cutodo TO cutodo_app;
-- GRANT USAGE ON SCHEMA public TO cutodo_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cutodo_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cutodo_app;

-- ============================================
-- MAINTENANCE
-- ============================================

-- Run these periodically via cron job:
-- SELECT cleanup_expired_sessions();
-- SELECT cleanup_expired_tokens();

-- Vacuum and analyze (PostgreSQL maintenance)
-- VACUUM ANALYZE users;
-- VACUUM ANALYZE tasks;
-- VACUUM ANALYZE sessions;

COMMENT ON TABLE users IS 'User accounts with authentication credentials';
COMMENT ON TABLE tasks IS 'User tasks and activities';
COMMENT ON TABLE sessions IS 'Active user sessions (optional)';

-- ============================================
-- SCHEMA VERSION
-- ============================================
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

INSERT INTO schema_version (version, description) VALUES
(1, 'Initial schema with users, tasks, and sessions tables')
ON CONFLICT DO NOTHING;

-- Success message
DO $$
BEGIN
    RAISE NOTICE '✅ Database schema setup complete!';
    RAISE NOTICE 'Tables created: users, tasks, sessions';
    RAISE NOTICE 'Indexes, triggers, and constraints applied';
END $$;
