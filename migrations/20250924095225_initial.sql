-- Enable UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- =====================
-- ENUM TYPES
-- =====================
CREATE TYPE user_role AS ENUM ('admin', 'regular');
CREATE TYPE user_status AS ENUM ('active', 'disactive');
CREATE TYPE apartment_condition AS ENUM ('new', 'repaired', 'old');
CREATE TYPE sale_type AS ENUM ('buy', 'rent');
-- =====================
-- USERS
-- =====================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone_number VARCHAR(50) NOT NULL,
    password TEXT NOT NULL,
    picture TEXT,
    role user_role NOT NULL DEFAULT 'regular',
    status user_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- =====================
-- APARTMENTS
-- =====================
CREATE TABLE apartments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    rooms INTEGER,
    area DOUBLE PRECISION,
    floor INTEGER,
    has_elevator BOOLEAN,
    condition apartment_condition NOT NULL,
    sale_type sale_type NOT NULL,
    requirements TEXT,
    has_garden BOOLEAN,
    distance_to_kindergarten DOUBLE PRECISION,
    distance_to_school DOUBLE PRECISION,
    distance_to_hospital DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- =====================
-- APARTMENT PICTURES
-- =====================
CREATE TABLE apartment_pictures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    apartment_id UUID NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- =====================
-- ADDRESSES
-- =====================
CREATE TABLE addresses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    apartment_id UUID NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
    street_address TEXT NOT NULL,
    city VARCHAR(100) NOT NULL,
    state_or_region VARCHAR(100) NOT NULL,
    county_or_district VARCHAR(100),
    postal_code VARCHAR(20) NOT NULL,
    country VARCHAR(100) NOT NULL,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- =====================
-- LISTINGS
-- =====================
CREATE TABLE listings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    apartment_id UUID NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    price DOUBLE PRECISION NOT NULL,
    available_from TIMESTAMPTZ,
    available_to TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- =====================
-- FAVORITES
-- =====================
CREATE TABLE favorites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    listing_id UUID NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, listing_id)
);
-- =====================
-- OAUTH USERS
-- =====================
CREATE TABLE oauth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exp TIMESTAMPTZ NOT NULL,
    iat TIMESTAMPTZ NOT NULL,
    iss VARCHAR(255) NOT NULL,
    sub VARCHAR(255) NOT NULL,
    at_hash VARCHAR(255),
    email VARCHAR(100),
    family_name VARCHAR(100),
    given_name VARCHAR(100),
    phone_number VARCHAR(50),
    name VARCHAR(100),
    picture TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- =====================
-- SESSIONS
-- =====================
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Index to quickly find sessions by token
CREATE INDEX idx_sessions_token ON sessions(session_token);
-- Index for checking valid sessions per user
CREATE INDEX idx_sessions_user_id_expires_at ON sessions(user_id, expires_at);