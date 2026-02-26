CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- USERS
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_hash TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    risk_profile_score INTEGER,
    risk_profile_updated_at TIMESTAMP
);

-- DEVICES
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_hash TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    first_seen_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT FALSE,
    integrity_flags JSONB
);

-- BENEFICIARIES
CREATE TABLE beneficiaries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    beneficiary_hash TEXT NOT NULL,
    label TEXT,
    first_added_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    is_trusted BOOLEAN DEFAULT FALSE,
    UNIQUE(user_id, beneficiary_hash)
);

-- EVENTS
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id),
    event_type TEXT NOT NULL,
    geo TEXT,
    context JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    queued BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMP
);

-- DECISIONS
CREATE TABLE decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    risk_score INTEGER NOT NULL,
    decision TEXT NOT NULL,
    reasons JSONB,
    model_version TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    type TEXT NOT NULL,                 
    status TEXT NOT NULL DEFAULT 'PENDING', 
    otp_code TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);