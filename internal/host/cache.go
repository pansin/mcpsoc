package host

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ResultCache 结果缓存
type ResultCache struct {
	logger *logrus.Logger
	cache  map[string]*CacheEntry
	mu     sync.RWMutex
	maxSize int
	defaultTTL time.Duration
}

// NewResultCache 创建新的结果缓存
func NewResultCache(logger *logrus.Logger) *ResultCache {
	cache := &ResultCache{
		logger:     logger,
		cache:      make(map[string]*CacheEntry),
		maxSize:    1000, // 默认最大缓存1000个条目
		defaultTTL: time.Hour, // 默认TTL 1小时
	}

	// 启动清理协程
	go cache.startCleanupWorker()

	return cache
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Key        string                 `json:"key"`
	Value      *OrchestratedResult    `json:"value"`
	CreatedAt  time.Time              `json:"created_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
	AccessedAt time.Time              `json:"accessed_at"`
	AccessCount int                   `json:"access_count"`
	Context    map[string]interface{} `json:"context"`
}

// CacheInfo 缓存信息
type CacheInfo struct {
	CacheHit    bool          `json:"cache_hit"`
	CacheAge    time.Duration `json:"cache_age"`
	OriginalID  string        `json:"original_id"`
	AccessCount int           `json:"access_count"`
}

// Get 获取缓存结果
func (rc *ResultCache) Get(query string, context map[string]interface{}) *OrchestratedResult {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	key := rc.generateCacheKey(query, context)
	entry, exists := rc.cache[key]

	if !exists {
		rc.logger.WithField("cache_key", key).Debug("Cache miss")
		return nil
	}

	// 检查是否过期
	if entry.ExpiresAt.Before(time.Now()) {
		rc.logger.WithField("cache_key", key).Debug("Cache entry expired")
		// 延迟删除，避免在读锁中执行删除操作
		go rc.deleteExpired(key)
		return nil
	}

	// 更新访问信息
	go rc.updateAccess(key)

	rc.logger.WithFields(logrus.Fields{
		"cache_key":    key,
		"access_count": entry.AccessCount,
		"age":          time.Since(entry.CreatedAt),
	}).Debug("Cache hit")

	return entry.Value
}

// Set 设置缓存结果
func (rc *ResultCache) Set(query string, context map[string]interface{}, result *OrchestratedResult, ttl time.Duration) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	key := rc.generateCacheKey(query, context)

	// 检查缓存大小限制
	if len(rc.cache) >= rc.maxSize {
		rc.evictOldest()
	}

	if ttl == 0 {
		ttl = rc.defaultTTL
	}

	entry := &CacheEntry{
		Key:         key,
		Value:       result,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
		AccessedAt:  time.Now(),
		AccessCount: 0,
		Context:     context,
	}

	rc.cache[key] = entry

	rc.logger.WithFields(logrus.Fields{
		"cache_key": key,
		"ttl":       ttl,
		"query_id":  result.QueryID,
	}).Debug("Cache entry created")
}

// Delete 删除缓存条目
func (rc *ResultCache) Delete(query string, context map[string]interface{}) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	key := rc.generateCacheKey(query, context)
	delete(rc.cache, key)

	rc.logger.WithField("cache_key", key).Debug("Cache entry deleted")
}

// Clear 清空缓存
func (rc *ResultCache) Clear() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache = make(map[string]*CacheEntry)
	rc.logger.Info("Cache cleared")
}

// GetStats 获取缓存统计信息
func (rc *ResultCache) GetStats() *CacheStats {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	stats := &CacheStats{
		TotalEntries: len(rc.cache),
		MaxSize:      rc.maxSize,
		DefaultTTL:   rc.defaultTTL,
	}

	var totalAccess int
	oldestEntry := time.Now()
	newestEntry := time.Time{}

	for _, entry := range rc.cache {
		totalAccess += entry.AccessCount
		if entry.CreatedAt.Before(oldestEntry) {
			oldestEntry = entry.CreatedAt
		}
		if entry.CreatedAt.After(newestEntry) {
			newestEntry = entry.CreatedAt
		}
	}

	if len(rc.cache) > 0 {
		stats.AverageAccess = float64(totalAccess) / float64(len(rc.cache))
		stats.OldestEntry = time.Since(oldestEntry)
		stats.NewestEntry = time.Since(newestEntry)
	}

	return stats
}

// SetMaxSize 设置最大缓存大小
func (rc *ResultCache) SetMaxSize(size int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.maxSize = size

	// 如果当前缓存超过新的大小限制，进行清理
	for len(rc.cache) > rc.maxSize {
		rc.evictOldest()
	}

	rc.logger.WithField("max_size", size).Info("Cache max size updated")
}

// SetDefaultTTL 设置默认TTL
func (rc *ResultCache) SetDefaultTTL(ttl time.Duration) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.defaultTTL = ttl
	rc.logger.WithField("default_ttl", ttl).Info("Cache default TTL updated")
}

// generateCacheKey 生成缓存键
func (rc *ResultCache) generateCacheKey(query string, context map[string]interface{}) string {
	// 创建一个包含查询和上下文的结构
	keyData := struct {
		Query   string                 `json:"query"`
		Context map[string]interface{} `json:"context"`
	}{
		Query:   query,
		Context: context,
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(keyData)
	if err != nil {
		// 如果序列化失败，使用简单的查询字符串
		return fmt.Sprintf("query:%s", query)
	}

	// 生成MD5哈希
	hash := md5.Sum(jsonData)
	return fmt.Sprintf("cache:%x", hash)
}

// updateAccess 更新访问信息
func (rc *ResultCache) updateAccess(key string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if entry, exists := rc.cache[key]; exists {
		entry.AccessedAt = time.Now()
		entry.AccessCount++
	}
}

// deleteExpired 删除过期条目
func (rc *ResultCache) deleteExpired(key string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	delete(rc.cache, key)
}

// evictOldest 驱逐最旧的条目
func (rc *ResultCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range rc.cache {
		if entry.AccessedAt.Before(oldestTime) {
			oldestTime = entry.AccessedAt
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(rc.cache, oldestKey)
		rc.logger.WithFields(logrus.Fields{
			"evicted_key": oldestKey,
			"last_access": oldestTime,
		}).Debug("Cache entry evicted")
	}
}

// startCleanupWorker 启动清理工作器
func (rc *ResultCache) startCleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute) // 每5分钟清理一次
	defer ticker.Stop()

	for range ticker.C {
		rc.cleanupExpired()
	}
}

// cleanupExpired 清理过期条目
func (rc *ResultCache) cleanupExpired() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	now := time.Now()
	expiredKeys := []string{}

	for key, entry := range rc.cache {
		if entry.ExpiresAt.Before(now) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(rc.cache, key)
	}

	if len(expiredKeys) > 0 {
		rc.logger.WithField("expired_count", len(expiredKeys)).Debug("Cleaned up expired cache entries")
	}
}

// GetCacheEntries 获取缓存条目（用于调试）
func (rc *ResultCache) GetCacheEntries() map[string]*CacheEntry {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	entries := make(map[string]*CacheEntry)
	for k, v := range rc.cache {
		// 创建副本以避免并发问题
		entryCopy := *v
		entries[k] = &entryCopy
	}

	return entries
}

// InvalidateByPattern 根据模式失效缓存条目
func (rc *ResultCache) InvalidateByPattern(pattern string) int {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	invalidatedCount := 0
	keysToDelete := []string{}

	for key, entry := range rc.cache {
		// 检查查询中是否包含模式
		if contains([]string{entry.Value.Query}, pattern) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(rc.cache, key)
		invalidatedCount++
	}

	rc.logger.WithFields(logrus.Fields{
		"pattern":           pattern,
		"invalidated_count": invalidatedCount,
	}).Info("Cache entries invalidated by pattern")

	return invalidatedCount
}

// Warmup 预热缓存
func (rc *ResultCache) Warmup(queries []WarmupQuery) {
	rc.logger.WithField("query_count", len(queries)).Info("Starting cache warmup")

	for _, query := range queries {
		// 这里可以实现预热逻辑
		// 通常是预先执行一些常见查询并缓存结果
		key := rc.generateCacheKey(query.Query, query.Context)
		rc.logger.WithField("cache_key", key).Debug("Warmup query processed")
	}

	rc.logger.Info("Cache warmup completed")
}

// CacheStats 缓存统计信息
type CacheStats struct {
	TotalEntries  int           `json:"total_entries"`
	MaxSize       int           `json:"max_size"`
	DefaultTTL    time.Duration `json:"default_ttl"`
	AverageAccess float64       `json:"average_access"`
	OldestEntry   time.Duration `json:"oldest_entry"`
	NewestEntry   time.Duration `json:"newest_entry"`
}

// WarmupQuery 预热查询
type WarmupQuery struct {
	Query   string                 `json:"query"`
	Context map[string]interface{} `json:"context"`
}