package storage

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// TimescaleDB 时序数据库支持
type TimescaleDB struct {
	*PostgresDatabase
}

// NewTimescaleDB 创建TimescaleDB实例
func NewTimescaleDB(postgres *PostgresDatabase) *TimescaleDB {
	return &TimescaleDB{PostgresDatabase: postgres}
}

// EnableTimescaleDB 启用TimescaleDB扩展
func (t *TimescaleDB) EnableTimescaleDB() error {
	return t.db.Exec("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;").Error
}

// CreateHypertables 创建超表
func (t *TimescaleDB) CreateHypertables() error {
	hypertables := []struct {
		table     string
		timeCol   string
		chunkTime string
	}{
		{"security_events", "timestamp", "1 day"},
		{"system_metrics", "timestamp", "1 hour"},
		{"audit_logs", "timestamp", "1 day"},
	}

	for _, ht := range hypertables {
		sql := fmt.Sprintf(
			"SELECT create_hypertable('%s', '%s', chunk_time_interval => INTERVAL '%s', if_not_exists => TRUE);",
			ht.table, ht.timeCol, ht.chunkTime,
		)
		if err := t.db.Exec(sql).Error; err != nil {
			return fmt.Errorf("failed to create hypertable %s: %w", ht.table, err)
		}
	}

	return nil
}

// CreateIndexes 创建时序优化索引
func (t *TimescaleDB) CreateIndexes() error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_security_events_source_time ON security_events (source, timestamp DESC);",
		"CREATE INDEX IF NOT EXISTS idx_security_events_severity_time ON security_events (severity, timestamp DESC);",
		"CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON system_metrics (metric_name, timestamp DESC);",
	}

	for _, idx := range indexes {
		if err := t.db.Exec(idx).Error; err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// 时序查询辅助方法

// GetSecurityEventsByTimeRange 按时间范围查询安全事件
func (t *TimescaleDB) GetSecurityEventsByTimeRange(start, end time.Time, limit int) ([]SecurityEvent, error) {
	var events []SecurityEvent
	err := t.db.Where("timestamp BETWEEN ? AND ?", start, end).
		Order("timestamp DESC").
		Limit(limit).
		Find(&events).Error
	return events, err
}

// GetMetricsByTimeRange 按时间范围查询系统指标
func (t *TimescaleDB) GetMetricsByTimeRange(metricName string, start, end time.Time) ([]SystemMetric, error) {
	var metrics []SystemMetric
	err := t.db.Where("metric_name = ? AND timestamp BETWEEN ? AND ?", metricName, start, end).
		Order("timestamp ASC").
		Find(&metrics).Error
	return metrics, err
}