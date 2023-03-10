CREATE DATABASE webauthn;
USE webauthn;
CREATE TABLE public_key(
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    kty INT,
    alg INT,
    crv INT,
    x TINYBLOB,
    y TINYBLOB,
    n VARCHAR(256),
    e VARCHAR(3),
    PRIMARY KEY(id)
);

CREATE TABLE credential(
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(45) NOT NULL,
    credential_id BLOB NOT NULL UNIQUE,
    credential_type INT NOT NULL,
    credential_signcount INT UNSIGNED NOT NULL,
    be BOOL,
    bs BOOL,
    fk_public_key INT UNSIGNED NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY (fk_public_key) REFERENCES public_key(id)
);