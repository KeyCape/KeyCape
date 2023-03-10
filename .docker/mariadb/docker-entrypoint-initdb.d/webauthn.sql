CREATE DATABASE IF NOT EXISTS webauthn;

USE webauthn;

#CREATE TABLE IF NOT EXISTS public_key(
#    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
#    kty INT,
#    alg INT,
#    crv INT,
#    x TINYBLOB,
#    y TINYBLOB,
#    n VARCHAR(256),
#    e VARCHAR(3),
#    PRIMARY KEY(id)
#);

CREATE TABLE
    IF NOT EXISTS resource_owner (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        username VARCHAR(45) NOT NULL UNIQUE,
        PRIMARY KEY(id)
    );

CREATE TABLE
    IF NOT EXISTS credential(
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        fk_resource_owner_id INT UNSIGNED NOT NULL,
        #username VARCHAR(45) NOT NULL,
        credential_id BLOB NOT NULL UNIQUE,
        credential_type INT NOT NULL,
        credential_signcount INT UNSIGNED NOT NULL,
        be BOOL,
        bs BOOL,
        #fk_public_key INT UNSIGNED NOT NULL,
        kty INT,
        alg INT,
        crv INT,
        x TINYBLOB,
        y TINYBLOB,
        n VARCHAR(256),
        e VARCHAR(3),
        PRIMARY KEY(id),
        FOREIGN KEY (fk_resource_owner_id) REFERENCES resource_owner(id) #FOREIGN KEY (fk_public_key) REFERENCES public_key(id)
    );

# OpenID Connect
CREATE TABLE
    IF NOT EXISTS oidc_client(
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        client_type INT UNSIGNED NOT NULL,
        client_id VARCHAR(2048) NOT NULL UNIQUE,
        client_secret VARCHAR(2048) NOT NULL UNIQUE,
        app_name VARCHAR(256) NOT NULL,
        website_uri VARCHAR(512) NOT NULL,
        logo BLOB,
        PRIMARY KEY(id)
    );

CREATE TABLE
    IF NOT EXISTS oidc_client_uri(
        fk_oidc_client_id INT UNSIGNED NOT NULL,
        uri VARCHAR(512) NOT NULL,
        PRIMARY KEY(fk_oidc_client_id, uri),
        FOREIGN KEY (fk_oidc_client_id) REFERENCES oidc_client(id)
    );

CREATE TABLE
    IF NOT EXISTS oidc_scope_mapping(
        fk_oidc_client_id INT UNSIGNED NOT NULL,
        fk_resource_owner_id INT UNSIGNED NOT NULL,
        oidc BOOLEAN DEFAULT FALSE,
        FOREIGN KEY(fk_oidc_client_id) REFERENCES oidc_client(id),
        FOREIGN KEY(fk_resource_owner_id) REFERENCES resource_owner(id)
    );