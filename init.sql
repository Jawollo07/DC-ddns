-- Tabelle für DNS-Records
CREATE TABLE IF NOT EXISTS dns_records (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL,
    content TEXT NOT NULL,
    ttl INT DEFAULT 120,
    proxied BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_type (type)
);

-- Tabelle für IP-History
CREATE TABLE IF NOT EXISTS ip_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    record_id VARCHAR(255),
    old_ip VARCHAR(45),
    new_ip VARCHAR(45),
    change_type ENUM('AUTO', 'MANUAL', 'WEB'),
    changed_by VARCHAR(255) DEFAULT 'SYSTEM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (record_id) REFERENCES dns_records(id) ON DELETE CASCADE,
    INDEX idx_record_id (record_id),
    INDEX idx_created_at (created_at)
);

-- Tabelle für Bot-Statistiken
CREATE TABLE IF NOT EXISTS bot_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    total_updates INT DEFAULT 0,
    last_update TIMESTAMP NULL,
    last_auto_update TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabelle für System-Logs
CREATE TABLE IF NOT EXISTS system_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    source VARCHAR(100) DEFAULT 'SYSTEM',
    user_id VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_level (level),
    INDEX idx_created_at (created_at)
);

-- Tabelle für Web-Sessions
CREATE TABLE IF NOT EXISTS web_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_user_id (user_id),
    INDEX idx_login_time (login_time)
);

-- Initiale Bot-Statistik zeile einfügen
INSERT IGNORE INTO bot_stats (id, total_updates) VALUES (1, 0);

EXIT;
