CREATE TABLE threat_indicators (
    id BIGSERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    indicator_value VARCHAR(500) NOT NULL,
    confidence FLOAT NOT NULL DEFAULT 0.5,
    threat_types TEXT[],
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(100) NOT NULL,
    metadata JSONB,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);