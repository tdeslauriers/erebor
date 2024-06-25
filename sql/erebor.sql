-- calling this "ux session" to avoid using db key words and `*` quotes
-- represents the session cookie
CREATE TABLE uxsession (
    uuid CHAR(36) PRIMARY KEY,
    session_index VARCHAR(128),
    session_token VARCHAR(128),
    csrf_token VARCHAR(128),
    created_at TIMESTAMP,
    authenticated BOOLEAN,
    revoked BOOLEAN
);
CREATE UNIQUE INDEX idx_session_index ON uxsession(session_index);

-- access token
CREATE TABLE accesstoken (
    uuid CHAR(36) PRIMARY KEY,
    access_token VARCHAR(2048),
    token_expires TIMESTAMP,
    refresh_token CHAR(128),
    refresh_expires TIMESTAMP
);
CREATE INDEX idx_accesstoken_servicename ON accesstoken(service_name);
-- ux session to access token xref
CREATE TABLE uxsession_accesstoken (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uxsession_uuid CHAR(36),
    accesstoken_uuid CHAR(36),
    CONSTRAINT fk_uxsession_uuid_ux_session_accesstoken_xref FOREIGN kEY (uxsession_uuid) REFERENCES uxsession(uuid),
    CONSTRAINT fk_accesstoken_uuid_ux_session_accesstoken_xref FOREIGN kEY (accesstoken_uuid) REFERENCES accesstoken(uuid)
);
CREATE INDEX idx_session_uuid_uxsession_access_xref ON uxsession_accesstoken(uxsession_uuid);

-- oauth flow
CREATE TABLE oauthflow (
    uuid CHAR(36) PRIMARY KEY,
    state_index VARCHAR(128) NOT NULL,
    response_type VARCHAR(128) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    state VARCHAR(128) NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    redirect_url VARCHAR(2048) NOT NULL,
    created_at TIMESTAMP
);
CREATE UNIQUE INDEX idx_state_index ON oauthflow(state_index);
-- ux session to oauth flow xref
CREATE TABLE uxsession_oauthflow (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uxsession_uuid CHAR(36),
    oauthflow_uuid CHAR(36),
    CONSTRAINT fk_uxsession_uuid_ux_session_oauthflow_xref FOREIGN kEY (uxsession_uuid) REFERENCES uxsession(uuid),
    CONSTRAINT fk_oauthflow_uuid_ux_session_oauthflow_xref FOREIGN kEY (oauthflow_uuid) REFERENCES oauthflow(uuid)
);

-- service token
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
