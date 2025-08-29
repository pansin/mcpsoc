package storage

import (
	"fmt"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database 数据库接口
type Database interface {
	GetDB() *gorm.DB
	Close() error
	Migrate() error
}

// PostgresDatabase PostgreSQL数据库实现
type PostgresDatabase struct {
	db *gorm.DB
}

// NewDatabase 创建新的数据库连接
func NewDatabase(config config.DatabaseConfig) (Database, error) {
	dsn := config.GetDSN()
	
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// 配置连接池
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return &PostgresDatabase{db: db}, nil
}

// GetDB 获取数据库实例
func (d *PostgresDatabase) GetDB() *gorm.DB {
	return d.db
}

// Close 关闭数据库连接
func (d *PostgresDatabase) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Migrate 执行数据库迁移
func (d *PostgresDatabase) Migrate() error {
	return d.db.AutoMigrate(
		&SecurityEvent{},
		&ThreatIndicator{},
		&MCPServerInfo{},
		&QueryHistory{},
	)
}

// SecurityEvent 安全事件模型
type SecurityEvent struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Timestamp   time.Time `gorm:"index" json:"timestamp"`
	Source      string    `gorm:"index" json:"source"`
	EventType   string    `gorm:"index" json:"event_type"`
	Severity    string    `gorm:"index" json:"severity"`
	RawData     string    `gorm:"type:jsonb" json:"raw_data"`
	ProcessedData string  `gorm:"type:jsonb" json:"processed_data"`
	Entities    string    `gorm:"type:jsonb" json:"entities"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ThreatIndicator 威胁指标模型
type ThreatIndicator struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	IndicatorType string    `gorm:"index" json:"indicator_type"`
	IndicatorValue string   `gorm:"index" json:"indicator_value"`
	Confidence    float64   `json:"confidence"`
	ThreatTypes   string    `gorm:"type:text[]" json:"threat_types"`
	FirstSeen     time.Time `gorm:"index" json:"first_seen"`
	LastSeen      time.Time `gorm:"index" json:"last_seen"`
	Source        string    `gorm:"index" json:"source"`
	Metadata      string    `gorm:"type:jsonb" json:"metadata"`
	ExpiresAt     *time.Time `gorm:"index" json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// MCPServerInfo MCP服务器信息模型
type MCPServerInfo struct {
	ID           string    `gorm:"primaryKey" json:"id"`
	Name         string    `json:"name"`
	Type         string    `gorm:"index" json:"type"`
	Status       string    `gorm:"index" json:"status"`
	Capabilities string    `gorm:"type:jsonb" json:"capabilities"`
	LastSeen     time.Time `gorm:"index" json:"last_seen"`
	Metadata     string    `gorm:"type:jsonb" json:"metadata"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// QueryHistory 查询历史模型
type QueryHistory struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       string    `gorm:"index" json:"user_id"`
	QueryType    string    `gorm:"index" json:"query_type"`
	QueryText    string    `json:"query_text"`
	QueryParams  string    `gorm:"type:jsonb" json:"query_params"`
	ResultCount  int       `json:"result_count"`
	ExecutionTime int64    `json:"execution_time"` // 毫秒
	Status       string    `gorm:"index" json:"status"`
	ErrorMessage string    `json:"error_message"`
	CreatedAt    time.Time `gorm:"index" json:"created_at"`
}

// SecurityEventRepository 安全事件仓库
type SecurityEventRepository struct {
	db *gorm.DB
}

// NewSecurityEventRepository 创建安全事件仓库
func NewSecurityEventRepository(db *gorm.DB) *SecurityEventRepository {
	return &SecurityEventRepository{db: db}
}

// Create 创建安全事件
func (r *SecurityEventRepository) Create(event *SecurityEvent) error {
	return r.db.Create(event).Error
}

// GetByID 根据ID获取安全事件
func (r *SecurityEventRepository) GetByID(id uint) (*SecurityEvent, error) {
	var event SecurityEvent
	err := r.db.First(&event, id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// List 列出安全事件
func (r *SecurityEventRepository) List(limit, offset int, filters map[string]interface{}) ([]SecurityEvent, error) {
	var events []SecurityEvent
	query := r.db.Model(&SecurityEvent{})

	// 应用过滤器
	for key, value := range filters {
		switch key {
		case "source":
			query = query.Where("source = ?", value)
		case "event_type":
			query = query.Where("event_type = ?", value)
		case "severity":
			query = query.Where("severity = ?", value)
		case "time_range":
			if timeRange, ok := value.(map[string]time.Time); ok {
				if start, exists := timeRange["start"]; exists {
					query = query.Where("timestamp >= ?", start)
				}
				if end, exists := timeRange["end"]; exists {
					query = query.Where("timestamp <= ?", end)
				}
			}
		}
	}

	err := query.Order("timestamp DESC").Limit(limit).Offset(offset).Find(&events).Error
	return events, err
}

// Count 统计安全事件数量
func (r *SecurityEventRepository) Count(filters map[string]interface{}) (int64, error) {
	var count int64
	query := r.db.Model(&SecurityEvent{})

	// 应用过滤器
	for key, value := range filters {
		switch key {
		case "source":
			query = query.Where("source = ?", value)
		case "event_type":
			query = query.Where("event_type = ?", value)
		case "severity":
			query = query.Where("severity = ?", value)
		}
	}

	err := query.Count(&count).Error
	return count, err
}

// ThreatIndicatorRepository 威胁指标仓库
type ThreatIndicatorRepository struct {
	db *gorm.DB
}

// NewThreatIndicatorRepository 创建威胁指标仓库
func NewThreatIndicatorRepository(db *gorm.DB) *ThreatIndicatorRepository {
	return &ThreatIndicatorRepository{db: db}
}

// Create 创建威胁指标
func (r *ThreatIndicatorRepository) Create(indicator *ThreatIndicator) error {
	return r.db.Create(indicator).Error
}

// GetByValue 根据值获取威胁指标
func (r *ThreatIndicatorRepository) GetByValue(indicatorType, value string) (*ThreatIndicator, error) {
	var indicator ThreatIndicator
	err := r.db.Where("indicator_type = ? AND indicator_value = ?", indicatorType, value).First(&indicator).Error
	if err != nil {
		return nil, err
	}
	return &indicator, nil
}

// Search 搜索威胁指标
func (r *ThreatIndicatorRepository) Search(query string, limit int) ([]ThreatIndicator, error) {
	var indicators []ThreatIndicator
	err := r.db.Where("indicator_value ILIKE ?", "%"+query+"%").
		Limit(limit).
		Order("confidence DESC").
		Find(&indicators).Error
	return indicators, err
}

// QueryHistoryRepository 查询历史仓库
type QueryHistoryRepository struct {
	db *gorm.DB
}

// NewQueryHistoryRepository 创建查询历史仓库
func NewQueryHistoryRepository(db *gorm.DB) *QueryHistoryRepository {
	return &QueryHistoryRepository{db: db}
}

// Create 创建查询历史
func (r *QueryHistoryRepository) Create(history *QueryHistory) error {
	return r.db.Create(history).Error
}

// GetByUserID 根据用户ID获取查询历史
func (r *QueryHistoryRepository) GetByUserID(userID string, limit, offset int) ([]QueryHistory, error) {
	var histories []QueryHistory
	err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&histories).Error
	return histories, err
}