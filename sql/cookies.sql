-- calling this "ux session" to avoid using db key words and `*` quotes
-- represents the auth cookie/session cookie
CREATE TABLE uxsession (
    uuid CHAR(36) PRIMARY KEY,
    session_token CHAR(36),
    csrf_token CHAR(36),
    created_at TIMESTAMP,
    expires_at TIMESTAMP
);
CREATE UNIQUE INDEX idx_session_token ON uxsession(session_token);