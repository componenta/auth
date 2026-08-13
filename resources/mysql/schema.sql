-- Canonical MySQL 8.4 schema for the built-in Componenta Auth SQL stores.
-- Keep credential identifiers byte-exact: identities may be case-sensitive and
-- session/bearer material must never be compared using a case-insensitive collation.

CREATE TABLE sessions (
    id VARBINARY(512) NOT NULL PRIMARY KEY,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_agent VARBINARY(1024) NOT NULL,
    expires_at DATETIME NOT NULL,
    absolute_expires_at DATETIME NOT NULL,
    regenerate_at DATETIME NOT NULL,
    replaced_by VARBINARY(512) NULL,
    created_at DATETIME NOT NULL,
    last_active_at DATETIME NOT NULL,
    attributes JSON NOT NULL,
    INDEX idx_sessions_subject_active (user_id, last_active_at),
    INDEX idx_sessions_replaced (replaced_by),
    INDEX idx_sessions_idle_expiry (expires_at, id),
    INDEX idx_sessions_absolute_expiry (absolute_expires_at, id)
) ENGINE=InnoDB;

CREATE TABLE remember_me_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    session_id VARBINARY(512) NOT NULL,
    previous_session_id VARBINARY(512) NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_remember_subject (user_id),
    INDEX idx_remember_session (session_id),
    INDEX idx_remember_previous_session (previous_session_id),
    INDEX idx_remember_expiry (expires_at, id)
) ENGINE=InnoDB;

CREATE TABLE otp_codes (
    destination VARBINARY(320) NOT NULL PRIMARY KEY,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    challenge_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    verifier CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    attempts INT UNSIGNED NOT NULL,
    INDEX idx_otp_expiry (expires_at, destination)
) ENGINE=InnoDB;

CREATE TABLE magic_link_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_magic_link_expiry (expires_at, id),
    INDEX idx_magic_link_used (used_at, id)
) ENGINE=InnoDB;

CREATE TABLE password_reset_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_password_reset_expiry (expires_at, id),
    INDEX idx_password_reset_used (used_at, id)
) ENGINE=InnoDB;

CREATE TABLE refresh_token_families (
    family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    cleanup_after BIGINT UNSIGNED NULL,
    revoked_at BIGINT UNSIGNED NULL,
    compromised_at BIGINT UNSIGNED NULL,
    lock_nonce CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    INDEX idx_refresh_family_subject (user_id),
    INDEX idx_refresh_family_cleanup (cleanup_after, family_id)
) ENGINE=InnoDB;

CREATE TABLE refresh_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    consumed_at BIGINT UNSIGNED NULL,
    revoked_at BIGINT UNSIGNED NULL,
    INDEX idx_refresh_token_family_expiry (family_id, expires_at),
    INDEX idx_refresh_token_subject (user_id),
    CONSTRAINT fk_refresh_family FOREIGN KEY (family_id)
        REFERENCES refresh_token_families(family_id)
) ENGINE=InnoDB;
