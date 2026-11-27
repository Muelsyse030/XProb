CREATE TABLE sessions (
    token_hash BINARY(32) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    PRIMARY KEY (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;