-- Canonical MySQL 8.4 / InnoDB schema for componenta/auth built-in stores.
-- Constraints, widths, binary collations and cleanup indexes are part of the
-- store contract. See resources/schema/README.md before adapting this schema.

CREATE TABLE sessions (
    id VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(1024) NOT NULL,
    expires_at DATETIME NOT NULL,
    absolute_expires_at DATETIME NOT NULL,
    regenerate_at DATETIME NOT NULL,
    replaced_by VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    created_at DATETIME NOT NULL,
    last_active_at DATETIME NOT NULL,
    attributes TEXT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_sessions_subject (user_id),
    KEY idx_sessions_replaced (replaced_by),
    KEY idx_sessions_cleanup_idle (replaced_by, expires_at),
    KEY idx_sessions_cleanup_absolute (absolute_expires_at)
) ENGINE=InnoDB;

CREATE TABLE remember_me_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_id VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    previous_session_id VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_remember_token (token),
    KEY idx_remember_subject (user_id),
    KEY idx_remember_session (session_id),
    KEY idx_remember_previous_session (previous_session_id),
    KEY idx_remember_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE otp_codes (
    destination VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    challenge_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    verifier CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    attempts INT UNSIGNED NOT NULL,
    PRIMARY KEY (destination),
    UNIQUE KEY uq_otp_challenge (challenge_id),
    KEY idx_otp_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE magic_link_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_magic_link_subject (user_id),
    UNIQUE KEY uq_magic_link_token (token),
    KEY idx_magic_link_expiry (expires_at),
    KEY idx_magic_link_used (used_at)
) ENGINE=InnoDB;

CREATE TABLE password_reset_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_password_reset_subject (user_id),
    UNIQUE KEY uq_password_reset_token (token),
    KEY idx_password_reset_expiry (expires_at),
    KEY idx_password_reset_used (used_at)
) ENGINE=InnoDB;

CREATE TABLE refresh_token_families (
    family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    revoked_at BIGINT UNSIGNED NULL,
    compromised_at BIGINT UNSIGNED NULL,
    lock_nonce CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (family_id),
    KEY idx_refresh_family_subject (user_id),
    KEY idx_refresh_family_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE refresh_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    consumed_at BIGINT UNSIGNED NULL,
    revoked_at BIGINT UNSIGNED NULL,
    PRIMARY KEY (token_hash),
    KEY idx_refresh_token_family (family_id),
    KEY idx_refresh_token_subject (user_id),
    KEY idx_refresh_token_expiry (expires_at),
    KEY idx_refresh_token_family_expiry (family_id, expires_at),
    CONSTRAINT fk_refresh_token_family
        FOREIGN KEY (family_id)
        REFERENCES refresh_token_families (family_id)
) ENGINE=InnoDB;
