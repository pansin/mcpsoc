CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    raw_data JSONB NOT NULL,
    processed_data JSONB,
    entities JSONB,
    tags TEXT[],
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);