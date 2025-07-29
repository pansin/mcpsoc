-- MCPSoc 数据库初始化脚本

-- 创建TimescaleDB扩展
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- 创建安全事件表
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    source VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    raw_data JSONB NOT NULL,
    processed_data JSONB,
    entities JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 创建时序分区
SELECT create_hypertable('security_events', 'timestamp', if_not_exists => TRUE);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_security_events_source_time ON security_events (source, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events (event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_entities ON security_events USING GIN (entities);

-- 创建威胁指标表
CREATE TABLE IF NOT EXISTS threat_indicators (
    id BIGSERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    indicator_value VARCHAR(500) NOT NULL,
    confidence FLOAT NOT NULL,
    threat_types TEXT[],
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    source VARCHAR(100) NOT NULL,
    metadata JSONB,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 创建时序分区
SELECT create_hypertable('threat_indicators', 'first_seen', if_not_exists => TRUE);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_threat_indicators_type_value ON threat_indicators (indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_source ON threat_indicators (source, first_seen DESC);

-- 创建MCP服务器信息表
CREATE TABLE IF NOT EXISTS mcp_server_infos (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    capabilities JSONB,
    last_seen TIMESTAMPTZ NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_mcp_server_infos_type ON mcp_server_infos (type);
CREATE INDEX IF NOT EXISTS idx_mcp_server_infos_status ON mcp_server_infos (status);
CREATE INDEX IF NOT EXISTS idx_mcp_server_infos_last_seen ON mcp_server_infos (last_seen DESC);

-- 创建查询历史表
CREATE TABLE IF NOT EXISTS query_histories (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255),
    query_type VARCHAR(50) NOT NULL,
    query_text TEXT NOT NULL,
    query_params JSONB,
    result_count INTEGER DEFAULT 0,
    execution_time BIGINT DEFAULT 0,
    status VARCHAR(50) NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 创建时序分区
SELECT create_hypertable('query_histories', 'created_at', if_not_exists => TRUE);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_query_histories_user_id ON query_histories (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_histories_type ON query_histories (query_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_histories_status ON query_histories (status, created_at DESC);

-- 插入示例数据
INSERT INTO security_events (timestamp, source, event_type, severity, raw_data, processed_data, entities) VALUES
(NOW() - INTERVAL '1 hour', 'firewall', 'connection_blocked', 'high', 
 '{"src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "dst_port": 22, "protocol": "tcp"}',
 '{"threat_level": "high", "action": "blocked", "rule_id": "block_ssh_external"}',
 '{"src_ip": {"type": "ip", "value": "192.168.1.100", "reputation": "malicious"}, "dst_ip": {"type": "ip", "value": "10.0.0.5", "reputation": "internal"}}'),

(NOW() - INTERVAL '30 minutes', 'waf', 'sql_injection_attempt', 'critical',
 '{"src_ip": "203.0.113.10", "dst_ip": "10.0.0.1", "url": "/login.php", "payload": "1'' OR 1=1--"}',
 '{"threat_level": "critical", "action": "blocked", "attack_type": "sql_injection"}',
 '{"src_ip": {"type": "ip", "value": "203.0.113.10", "reputation": "suspicious"}, "url": {"type": "url", "value": "/login.php", "category": "authentication"}}'),

(NOW() - INTERVAL '15 minutes', 'antivirus', 'malware_detected', 'high',
 '{"file_path": "/tmp/malware.exe", "hash": "d41d8cd98f00b204e9800998ecf8427e", "virus_name": "Trojan.Generic"}',
 '{"threat_level": "high", "action": "quarantined", "scan_engine": "clamav"}',
 '{"file": {"type": "file", "path": "/tmp/malware.exe", "hash": "d41d8cd98f00b204e9800998ecf8427e", "threat": "trojan"}}');

-- 插入威胁指标示例数据
INSERT INTO threat_indicators (indicator_type, indicator_value, confidence, threat_types, first_seen, last_seen, source, metadata) VALUES
('ip', '192.168.1.100', 0.95, ARRAY['malware', 'botnet'], NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', 'threat_intel_feed', 
 '{"country": "CN", "asn": "AS4134", "description": "Known botnet C&C server"}'),

('domain', 'malicious.com', 0.88, ARRAY['phishing', 'malware'], NOW() - INTERVAL '1 day', NOW() - INTERVAL '6 hours', 'threat_intel_feed',
 '{"registrar": "Example Registrar", "creation_date": "2023-01-01", "description": "Phishing domain"}'),

('hash', 'd41d8cd98f00b204e9800998ecf8427e', 0.92, ARRAY['trojan', 'backdoor'], NOW() - INTERVAL '3 days', NOW() - INTERVAL '15 minutes', 'antivirus',
 '{"file_type": "PE32", "size": 1024000, "description": "Generic trojan backdoor"}}');

-- 插入MCP服务器信息示例数据
INSERT INTO mcp_server_infos (id, name, type, status, capabilities, last_seen, metadata) VALUES
('firewall-pfsense-01', 'pfSense Firewall', 'firewall', 'connected', 
 '{"tools": ["get_firewall_logs", "block_ip", "unblock_ip"], "resources": ["firewall://logs/realtime"]}',
 NOW(), '{"version": "1.0.0", "endpoint": "http://localhost:8081/mcp"}'),

('waf-modsecurity-01', 'ModSecurity WAF', 'waf', 'connected',
 '{"tools": ["get_waf_logs", "block_request"], "resources": ["waf://logs/realtime"]}',
 NOW(), '{"version": "1.0.0", "endpoint": "stdio"}'),

('av-clamav-01', 'ClamAV Antivirus', 'antivirus', 'connected',
 '{"tools": ["scan_file", "get_scan_results"], "resources": ["av://quarantine"]}',
 NOW(), '{"version": "1.0.0", "endpoint": "tcp://localhost:8082"}}');

-- 插入查询历史示例数据
INSERT INTO query_histories (user_id, query_type, query_text, query_params, result_count, execution_time, status) VALUES
('demo_user', 'natural', '查找过去24小时内的高危威胁事件', '{"time_range": "24h", "severity": "high"}', 3, 1200, 'success'),
('demo_user', 'structured', 'SELECT * FROM security_events WHERE severity = ''high''', '{"data_source": "security_events"}', 5, 800, 'success'),
('demo_user', 'natural', '分析来自192.168.1.100的可疑活动', '{"ip_address": "192.168.1.100"}', 2, 1500, 'success');

-- 创建更新时间戳的触发器函数
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 为需要的表创建触发器
CREATE TRIGGER update_security_events_updated_at BEFORE UPDATE ON security_events FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_threat_indicators_updated_at BEFORE UPDATE ON threat_indicators FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_mcp_server_infos_updated_at BEFORE UPDATE ON mcp_server_infos FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();