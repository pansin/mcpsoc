CREATE TABLE mcp_servers (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    server_type VARCHAR(50) NOT NULL,
    vendor VARCHAR(100),
    version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    endpoint_url TEXT,
    capabilities JSONB,
    config JSONB,
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);