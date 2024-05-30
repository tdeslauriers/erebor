-- calling this "ux session" to avoid using db key words and `*` quotes
-- represents the auth cookie/session cookie
CREATE TABLE uxsession (
    uuid CHAR(36) PRIMARY KEY,
    session_token CHAR(128),
    csrf_token CHAR(128),
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked BOOLEAN
);
CREATE UNIQUE INDEX idx_session_token ON uxsession(session_token);
CREATE TABLE accesstoken (
    uuid CHAR(36) PRIMARY KEY,
    service_name VARCHAR(32),
    token VARCHAR(2048),
    token_expires TIMESTAMP,
    refresh_token CHAR(128),
    refresh_expires TIMESTAMP
);
CREATE INDEX idx_accesstoken_servicename ON accesstoken(service_name);
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
    service_name VARCHAR(32) NOT NULL,
    service_token VARCHAR(2048) NOT NULL,
    service_expires TIMESTAMP NOT NULL,
    refresh_token VARCHAR(128) NOT NULL,
    refresh_expires TIMESTAMP NOT NULL
);
CREATE INDEX idx_servicetoken_servicename ON servicetoken(service_name);
CREATE INDEX idx_servicetoken_refreshexpires ON servicetoken(refresh_expires);
CREATE TABLE oauthflow (
    uuid CHAR(36) PRIMARY KEY,
    nonce CHAR(128),
    state CHAR(128),
    redirect_url VARCHAR(512),
    created_at TIMESTAMP
);
CREATE UNIQUE INDEX idx_nonce ON oauthflow(nonce);
CREATE UNIQUE INDEX idx_state_param ON oauthflow(state_param);