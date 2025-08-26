package intelligence

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/detection"
	"github.com/sirupsen/logrus"
)

// ThreatIntelligenceEngine 威胁情报引擎
type ThreatIntelligenceEngine struct {
	logger    *logrus.Logger
	sources   map[string]IntelligenceSource
	cache     *IntelligenceCache
	mu        sync.RWMutex
	enabled   bool
	metrics   *IntelligenceMetrics
}

// NewThreatIntelligenceEngine 创建威胁情报引擎
func NewThreatIntelligenceEngine(logger *logrus.Logger) *ThreatIntelligenceEngine {
	return &ThreatIntelligenceEngine{
		logger:  logger,
		sources: make(map[string]IntelligenceSource),
		cache:   NewIntelligenceCache(),
		enabled: true,
		metrics: NewIntelligenceMetrics(),
	}
}

// IntelligenceSource 威胁情报源接口
type IntelligenceSource interface {
	GetName() string
	GetType() string
	QueryIOC(ctx context.Context, ioc *IOC) (*IntelligenceResult, error)
	IsEnabled() bool
	GetConfidence() float64
}

// IOC 威胁指标
type IOC struct {
	Type        string    `json:"type"`         // ip, domain, hash, url, email
	Value       string    `json:"value"`        // 指标值
	Source      string    `json:"source"`       // 来源
	FirstSeen   time.Time `json:"first_seen"`   // 首次发现时间
	LastSeen    time.Time `json:"last_seen"`    // 最后发现时间
	Confidence  float64   `json:"confidence"`   // 置信度
	Context     map[string]interface{} `json:"context"` // 上下文信息
}

// IntelligenceResult 威胁情报查询结果
type IntelligenceResult struct {
	IOC           *IOC                   `json:"ioc"`
	ThreatType    string                 `json:"threat_type"`
	Malicious     bool                   `json:"malicious"`
	Confidence    float64                `json:"confidence"`
	Description   string                 `json:"description"`
	Source        string                 `json:"source"`
	LastUpdated   time.Time              `json:"last_updated"`
	Tags          []string               `json:"tags"`
	Attributes    map[string]interface{} `json:"attributes"`
	RelatedIOCs   []*IOC                 `json:"related_iocs"`
}

// CorrelationResult 关联分析结果
type CorrelationResult struct {
	QueryIOC        *IOC                     `json:"query_ioc"`
	Matches         []*IntelligenceResult    `json:"matches"`
	RelatedThreats  []*ThreatCampaign        `json:"related_threats"`
	RiskScore       float64                  `json:"risk_score"`
	Recommendations []string                 `json:"recommendations"`
	AnalysisTime    time.Time                `json:"analysis_time"`
}

// ThreatCampaign 威胁活动
type ThreatCampaign struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ThreatActor string    `json:"threat_actor"`
	TTPs        []string  `json:"ttps"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Confidence  float64   `json:"confidence"`
}

// AnalyzeAlert 分析告警的威胁情报
func (tie *ThreatIntelligenceEngine) AnalyzeAlert(ctx context.Context, alert *detection.ThreatAlert) (*CorrelationResult, error) {
	if !tie.enabled {
		return nil, nil
	}

	tie.logger.WithField("alert_id", alert.ID).Info("Starting threat intelligence analysis")

	// 提取IOCs
	iocs := tie.extractIOCs(alert)
	if len(iocs) == 0 {
		return nil, fmt.Errorf("no IOCs found in alert")
	}

	var allMatches []*IntelligenceResult
	var relatedThreats []*ThreatCampaign

	// 对每个IOC进行威胁情报查询
	for _, ioc := range iocs {
		matches, err := tie.queryAllSources(ctx, ioc)
		if err != nil {
			tie.logger.WithError(err).WithField("ioc", ioc.Value).Warn("Failed to query IOC")
			continue
		}

		allMatches = append(allMatches, matches...)

		// 查找相关威胁活动
		campaigns := tie.findRelatedCampaigns(matches)
		relatedThreats = append(relatedThreats, campaigns...)
	}

	// 计算风险评分
	riskScore := tie.calculateRiskScore(allMatches, relatedThreats)

	// 生成推荐
	recommendations := tie.generateRecommendations(allMatches, relatedThreats, riskScore)

	result := &CorrelationResult{
		QueryIOC:        iocs[0], // 主要IOC
		Matches:         allMatches,
		RelatedThreats:  relatedThreats,
		RiskScore:       riskScore,
		Recommendations: recommendations,
		AnalysisTime:    time.Now(),
	}

	tie.metrics.IncrementAnalysisCount()
	if len(allMatches) > 0 {
		tie.metrics.IncrementMatchCount(len(allMatches))
	}

	return result, nil
}

// extractIOCs 从告警中提取IOCs
func (tie *ThreatIntelligenceEngine) extractIOCs(alert *detection.ThreatAlert) []*IOC {
	var iocs []*IOC

	// 从源数据中提取IOCs
	if alert.SourceData != nil {
		// 提取IP地址
		if ip, ok := alert.SourceData["ip_address"].(string); ok && tie.isValidIP(ip) {
			iocs = append(iocs, &IOC{
				Type:       "ip",
				Value:      ip,
				Source:     "alert",
				FirstSeen:  alert.Timestamp,
				LastSeen:   alert.Timestamp,
				Confidence: 0.8,
			})
		}

		// 提取域名
		if domain, ok := alert.SourceData["domain"].(string); ok && tie.isValidDomain(domain) {
			iocs = append(iocs, &IOC{
				Type:       "domain",
				Value:      domain,
				Source:     "alert",
				FirstSeen:  alert.Timestamp,
				LastSeen:   alert.Timestamp,
				Confidence: 0.8,
			})
		}

		// 提取文件哈希
		if hash, ok := alert.SourceData["file_hash"].(string); ok && tie.isValidHash(hash) {
			iocs = append(iocs, &IOC{
				Type:       "hash",
				Value:      hash,
				Source:     "alert",
				FirstSeen:  alert.Timestamp,
				LastSeen:   alert.Timestamp,
				Confidence: 0.9,
			})
		}

		// 提取URL
		if url, ok := alert.SourceData["url"].(string); ok && tie.isValidURL(url) {
			iocs = append(iocs, &IOC{
				Type:       "url",
				Value:      url,
				Source:     "alert",
				FirstSeen:  alert.Timestamp,
				LastSeen:   alert.Timestamp,
				Confidence: 0.8,
			})
		}
	}

	// 从指标中提取IOCs
	for _, indicator := range alert.Indicators {
		parts := strings.SplitN(indicator, ":", 2)
		if len(parts) == 2 {
			iocType := parts[0]
			iocValue := parts[1]

			if tie.isValidIOCType(iocType) && tie.isValidIOCValue(iocType, iocValue) {
				iocs = append(iocs, &IOC{
					Type:       iocType,
					Value:      iocValue,
					Source:     "indicator",
					FirstSeen:  alert.Timestamp,
					LastSeen:   alert.Timestamp,
					Confidence: 0.7,
				})
			}
		}
	}

	return iocs
}

// queryAllSources 查询所有威胁情报源
func (tie *ThreatIntelligenceEngine) queryAllSources(ctx context.Context, ioc *IOC) ([]*IntelligenceResult, error) {
	tie.mu.RLock()
	defer tie.mu.RUnlock()

	// 首先检查缓存
	if cached := tie.cache.Get(ioc); cached != nil {
		return []*IntelligenceResult{cached}, nil
	}

	var results []*IntelligenceResult

	// 查询所有启用的情报源
	for _, source := range tie.sources {
		if !source.IsEnabled() {
			continue
		}

		result, err := source.QueryIOC(ctx, ioc)
		if err != nil {
			tie.logger.WithError(err).WithFields(logrus.Fields{
				"source": source.GetName(),
				"ioc":    ioc.Value,
			}).Warn("Failed to query intelligence source")
			continue
		}

		if result != nil && result.Malicious {
			results = append(results, result)
			
			// 缓存结果
			tie.cache.Set(ioc, result)
		}
	}

	return results, nil
}

// findRelatedCampaigns 查找相关威胁活动
func (tie *ThreatIntelligenceEngine) findRelatedCampaigns(matches []*IntelligenceResult) []*ThreatCampaign {
	campaignMap := make(map[string]*ThreatCampaign)

	for _, match := range matches {
		// 基于标签查找威胁活动
		for _, tag := range match.Tags {
			if strings.Contains(strings.ToLower(tag), "apt") || 
			   strings.Contains(strings.ToLower(tag), "campaign") {
				
				// 创建或更新威胁活动
				campaignID := strings.ToLower(tag)
				if campaign, exists := campaignMap[campaignID]; exists {
					campaign.Confidence = math.Max(campaign.Confidence, match.Confidence)
				} else {
					campaignMap[campaignID] = &ThreatCampaign{
						ID:          campaignID,
						Name:        tag,
						Description: fmt.Sprintf("威胁活动: %s", tag),
						FirstSeen:   match.LastUpdated,
						LastSeen:    match.LastUpdated,
						Confidence:  match.Confidence,
					}
				}
			}
		}
	}

	var campaigns []*ThreatCampaign
	for _, campaign := range campaignMap {
		campaigns = append(campaigns, campaign)
	}

	return campaigns
}

// calculateRiskScore 计算风险评分
func (tie *ThreatIntelligenceEngine) calculateRiskScore(matches []*IntelligenceResult, campaigns []*ThreatCampaign) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	// 基础风险评分
	baseScore := 0.0
	for _, match := range matches {
		if match.Malicious {
			baseScore += match.Confidence * 30 // 每个恶意IOC最多30分
		}
	}

	// 威胁活动加成
	campaignBonus := 0.0
	for _, campaign := range campaigns {
		campaignBonus += campaign.Confidence * 20 // 每个威胁活动最多20分
	}

	// 多源验证加成
	sourceCount := tie.countUniqueSources(matches)
	sourceBonus := float64(sourceCount-1) * 10 // 多源验证加成

	totalScore := baseScore + campaignBonus + sourceBonus
	return math.Min(100.0, totalScore) // 最高100分
}

// generateRecommendations 生成推荐
func (tie *ThreatIntelligenceEngine) generateRecommendations(matches []*IntelligenceResult, campaigns []*ThreatCampaign, riskScore float64) []string {
	var recommendations []string

	if riskScore >= 80 {
		recommendations = append(recommendations, "立即阻断所有相关IP和域名")
		recommendations = append(recommendations, "启动高级威胁响应流程")
	} else if riskScore >= 60 {
		recommendations = append(recommendations, "加强对相关资产的监控")
		recommendations = append(recommendations, "考虑临时阻断可疑连接")
	} else if riskScore >= 40 {
		recommendations = append(recommendations, "持续观察相关指标")
		recommendations = append(recommendations, "更新安全规则和检测逻辑")
	}

	if len(campaigns) > 0 {
		recommendations = append(recommendations, "关注相关威胁活动的最新动态")
	}

	if len(matches) > 2 {
		recommendations = append(recommendations, "进行深度威胁狩猎活动")
	}

	return recommendations
}

// 情报源管理
func (tie *ThreatIntelligenceEngine) RegisterSource(id string, source IntelligenceSource) {
	tie.mu.Lock()
	defer tie.mu.Unlock()

	tie.sources[id] = source
	tie.logger.WithFields(logrus.Fields{
		"source_id":   id,
		"source_name": source.GetName(),
		"source_type": source.GetType(),
	}).Info("Intelligence source registered")
}

func (tie *ThreatIntelligenceEngine) UnregisterSource(id string) {
	tie.mu.Lock()
	defer tie.mu.Unlock()

	delete(tie.sources, id)
	tie.logger.WithField("source_id", id).Info("Intelligence source unregistered")
}

// 验证方法
func (tie *ThreatIntelligenceEngine) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (tie *ThreatIntelligenceEngine) isValidDomain(domain string) bool {
	return len(domain) > 0 && strings.Contains(domain, ".")
}

func (tie *ThreatIntelligenceEngine) isValidHash(hash string) bool {
	// 检查MD5, SHA1, SHA256哈希格式
	hashLen := len(hash)
	return (hashLen == 32 || hashLen == 40 || hashLen == 64) && tie.isHex(hash)
}

func (tie *ThreatIntelligenceEngine) isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func (tie *ThreatIntelligenceEngine) isValidIOCType(iocType string) bool {
	validTypes := []string{"ip", "domain", "hash", "url", "email"}
	for _, t := range validTypes {
		if t == iocType {
			return true
		}
	}
	return false
}

func (tie *ThreatIntelligenceEngine) isValidIOCValue(iocType, value string) bool {
	switch iocType {
	case "ip":
		return tie.isValidIP(value)
	case "domain":
		return tie.isValidDomain(value)
	case "hash":
		return tie.isValidHash(value)
	case "url":
		return tie.isValidURL(value)
	case "email":
		return strings.Contains(value, "@")
	default:
		return false
	}
}

func (tie *ThreatIntelligenceEngine) isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func (tie *ThreatIntelligenceEngine) countUniqueSources(matches []*IntelligenceResult) int {
	sources := make(map[string]bool)
	for _, match := range matches {
		sources[match.Source] = true
	}
	return len(sources)
}

// 缓存实现
type IntelligenceCache struct {
	cache map[string]*CacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

type CacheEntry struct {
	Result    *IntelligenceResult
	ExpiresAt time.Time
}

func NewIntelligenceCache() *IntelligenceCache {
	return &IntelligenceCache{
		cache: make(map[string]*CacheEntry),
		ttl:   1 * time.Hour, // 默认1小时TTL
	}
}

func (ic *IntelligenceCache) Get(ioc *IOC) *IntelligenceResult {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", ioc.Type, ioc.Value)
	entry, exists := ic.cache[key]
	if !exists {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(ic.cache, key)
		return nil
	}

	return entry.Result
}

func (ic *IntelligenceCache) Set(ioc *IOC, result *IntelligenceResult) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	key := fmt.Sprintf("%s:%s", ioc.Type, ioc.Value)
	ic.cache[key] = &CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(ic.ttl),
	}
}

// 指标统计
type IntelligenceMetrics struct {
	mu            sync.RWMutex
	analysisCount int64
	matchCount    int64
	cacheHits     int64
	cacheMisses   int64
}

func NewIntelligenceMetrics() *IntelligenceMetrics {
	return &IntelligenceMetrics{}
}

func (im *IntelligenceMetrics) IncrementAnalysisCount() {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.analysisCount++
}

func (im *IntelligenceMetrics) IncrementMatchCount(count int) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.matchCount += int64(count)
}

func (im *IntelligenceMetrics) GetStats() map[string]interface{} {
	im.mu.RLock()
	defer im.mu.RUnlock()

	return map[string]interface{}{
		"analysis_count": im.analysisCount,
		"match_count":    im.matchCount,
		"cache_hits":     im.cacheHits,
		"cache_misses":   im.cacheMisses,
	}
}

