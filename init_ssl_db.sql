-- Connect to the PostgreSQL server as a superuser (e.g., postgres)
-- psql -U postgres

-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS ssl_database;

-- Connect to the database
\c ssl_database

-- Create the ssl_certificates table
CREATE TABLE IF NOT EXISTS ssl_certificates (
    key TEXT PRIMARY KEY,
    name TEXT,
    type TEXT,
    valid_from TIMESTAMP,
    valid_to TIMESTAMP,
    common_names TEXT,
    rsa_encryption BOOLEAN,
    sha_1_fingerprint TEXT,
    subject TEXT,
    issuer TEXT,
    ports TEXT,
    all_ip_addresses TEXT,
    connections TEXT,
    serial TEXT,
    warnings TEXT,
    errors TEXT,
    least_strength TEXT,
    subject_cn TEXT,
    subject_state TEXT,
    sujbect_country TEXT,
    subject_locality TEXT,
    subject_email TEXT,
    issuer_cn TEXT,
    issuer_state TEXT,
    issuer_country TEXT,
    issuer_locality TEXT,
    issuer_email TEXT,
    raw_output TEXT,
    raw_not_before TEXT,
    raw_not_after TEXT,
    md5sum TEXT,
    public_key_type TEXT,
    public_key_bits INTEGER,
    ciphers TEXT
);