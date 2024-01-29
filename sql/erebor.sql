-- calling this "ux session" to avoid using db key words and `*` quotes
-- represents the auth cookie/session cookie
CREATE TABLE uxsession (
    uuid CHAR(36) PRIMARY KEY,
    session_token CHAR(36),
    csrf_token CHAR(36),
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked BOOLEAN
);
CREATE UNIQUE INDEX idx_session_token ON uxsession(session_token);
CREATE TABLE accesstoken (
    uuid CHAR(36) PRIMARY KEY,
    access_token VARCHAR(1024),
    access_expires TIMESTAMP,
    refresh_token CHAR(36),
    refresh_expires TIMESTAMP
);
CREATE TABLE uxsession_accesstoken (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uxsession_uuid CHAR(36),
    accesstoken_uuid CHAR(36),
    CONSTRAINT fk_uxsession_uuid_ux_session_accesstoken_xref FOREIGN kEY (uxsession_uuid) REFERENCES uxsession(uuid),
    CONSTRAINT fk_accesstoken_uuid_ux_session_accesstoken_xref FOREIGN kEY (accesstoken_uuid) REFERENCES accesstoken(uuid)
);
CREATE INDEX idx_session_uuid_uxsession_access_xref ON uxsession_accesstoken(uxsession_uuid);
CREATE TABLE servicetoken (
    uuid CHAR(36) PRIMARY KEY,
    service_token VARCHAR(1024),
    service_expires TIMESTAMP,
    refresh_token CHAR(36),
    refresh_expires TIMESTAMP
);