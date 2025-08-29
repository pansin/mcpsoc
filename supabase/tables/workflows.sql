CREATE TABLE workflows (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    workflow_type VARCHAR(50) NOT NULL,
    trigger_conditions JSONB,
    actions JSONB,
    status VARCHAR(20) DEFAULT 'active',
    execution_count INTEGER DEFAULT 0,
    last_executed TIMESTAMPTZ,
    created_by VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);