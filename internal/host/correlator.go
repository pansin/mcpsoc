package host

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DataCorrelator 数据关联分析器
type DataCorrelator struct {
	logger *logrus.Logger
}

// NewDataCorrelator 创建新的数据关联分析器
func NewDataCorrelator(logger *logrus.Logger) *DataCorrelator {
	return &DataCorrelator{
		logger: logger,
	}
}

// AnalyzeData 分析数据并进行关联
func (dc *DataCorrelator) AnalyzeData(ctx context.Context, results *EnhancedResults, intent string) (*CorrelationResult, error) {
	dc.logger.WithFields(logrus.Fields{
		"intent":       intent,
		"data_sources": len(results.Sources),
	}).Info("Starting data correlation analysis")

	startTime := time.Now()

	correlationResult := &CorrelationResult{
		Status:        "analyzing",
		Intent:        intent,
		Correlations:  []DataCorrelation{},
		Patterns:      []ThreatPattern{},
		Anomalies:     []SecurityAnomaly{},
		Timeline:      []TimelineEvent{},
		Insights:      []AnalysisInsight{},
		Confidence:    0.0,
		StartTime:     startTime,
	}

	// 提取和标准化数据
	normalizedData := dc.extractAndNormalizeData(results)
	
	// 基于意图进行不同类型的关联分析
	switch intent {
	case "threat_analysis":
		dc.performThreatCorrelation(normalizedData, correlationResult)
	case "incident_response":
		dc.performIncidentCorrelation(normalizedData, correlationResult)
	case "log_analysis":
		dc.performLogCorrelation(normalizedData, correlationResult)
	default:
		dc.performGeneralCorrelation(normalizedData, correlationResult)
	}

	// 构建时间线
	dc.buildTimeline(normalizedData, correlationResult)

	// 检测异常
	dc.detectAnomalies(normalizedData, correlationResult)

	// 生成洞察
	dc.generateInsights(correlationResult)

	// 计算整体置信度
	correlationResult.Confidence = dc.calculateOverallConfidence(correlationResult)
	correlationResult.Status = "completed"
	correlationResult.EndTime = time.Now()
	correlationResult.Duration = correlationResult.EndTime.Sub(startTime)

	dc.logger.WithFields(logrus.Fields{
		"correlations": len(correlationResult.Correlations),
		"patterns":     len(correlationResult.Patterns),
		"anomalies":    len(correlationResult.Anomalies),
		"confidence":   correlationResult.Confidence,
		"duration":     correlationResult.Duration,
	}).Info("Data correlation analysis completed")

	return correlationResult, nil
}

// extractAndNormalizeData 提取和标准化数据
func (dc *DataCorrelator) extractAndNormalizeData(results *EnhancedResults) []*NormalizedDataPoint {
	var dataPoints []*NormalizedDataPoint

	for sourceID, sourceResult := range results.Sources {
		if !sourceResult.Success {
			continue
		}

		for _, data := range sourceResult.Data {
			if dataMap, ok := data.(map[string]interface{}); ok {
				normalized := dc.normalizeDataPoint(sourceID, dataMap)
				if normalized != nil {
					dataPoints = append(dataPoints, normalized)
				}
			}
		}
	}

	return dataPoints
}

// normalizeDataPoint 标准化数据点
func (dc *DataCorrelator) normalizeDataPoint(sourceID string, data map[string]interface{}) *NormalizedDataPoint {
	point := &NormalizedDataPoint{
		SourceID:   sourceID,
		Type:       dc.inferDataType(data),
		Timestamp:  dc.extractTimestamp(data),
		Attributes: make(map[string]interface{}),
	}

	// 提取标准化字段
	if ip := dc.extractField(data, "ip", "ip_address", "src_ip", "dst_ip", "client_ip"); ip != "" {
		point.IPAddress = ip
	}

	if domain := dc.extractField(data, "domain", "hostname", "host", "server_name"); domain != "" {
		point.Domain = domain
	}

	if user := dc.extractField(data, "user", "username", "account", "user_id"); user != "" {
		point.User = user
	}

	if process := dc.extractField(data, "process", "process_name", "command", "exe"); process != "" {
		point.Process = process
	}

	if file := dc.extractField(data, "file", "filename", "file_path", "path"); file != "" {
		point.File = file
	}

	// 复制所有原始属性
	for k, v := range data {
		point.Attributes[k] = v
	}

	return point
}

// performThreatCorrelation 执行威胁关联分析
func (dc *DataCorrelator) performThreatCorrelation(data []*NormalizedDataPoint, result *CorrelationResult) {
	// IP地址关联
	dc.correlateByIP(data, result)
	
	// 时间窗口关联
	dc.correlateByTimeWindow(data, result)
	
	// 用户行为关联
	dc.correlateByUser(data, result)
	
	// 检测已知威胁模式
	dc.detectKnownThreatPatterns(data, result)
}

// performIncidentCorrelation 执行事件关联分析
func (dc *DataCorrelator) performIncidentCorrelation(data []*NormalizedDataPoint, result *CorrelationResult) {
	// 事件序列关联
	dc.correlateEventSequence(data, result)
	
	// 影响范围分析
	dc.analyzeImpactScope(data, result)
	
	// 攻击链重建
	dc.reconstructAttackChain(data, result)
}

// performLogCorrelation 执行日志关联分析
func (dc *DataCorrelator) performLogCorrelation(data []*NormalizedDataPoint, result *CorrelationResult) {
	// 错误模式关联
	dc.correlateErrorPatterns(data, result)
	
	// 频率分析
	dc.analyzeFrequencyPatterns(data, result)
	
	// 地理位置关联
	dc.correlateByGeoLocation(data, result)
}

// performGeneralCorrelation 执行通用关联分析
func (dc *DataCorrelator) performGeneralCorrelation(data []*NormalizedDataPoint, result *CorrelationResult) {
	// 基础字段关联
	dc.correlateByCommonFields(data, result)
	
	// 统计分析
	dc.performStatisticalAnalysis(data, result)
}

// correlateByIP IP地址关联分析
func (dc *DataCorrelator) correlateByIP(data []*NormalizedDataPoint, result *CorrelationResult) {
	ipGroups := make(map[string][]*NormalizedDataPoint)
	
	for _, point := range data {
		if point.IPAddress != "" {
			ipGroups[point.IPAddress] = append(ipGroups[point.IPAddress], point)
		}
	}
	
	for ip, points := range ipGroups {
		if len(points) > 1 {
			correlation := DataCorrelation{
				Type:        "ip_correlation",
				Field:       "ip_address",
				Value:       ip,
				DataPoints:  points,
				Confidence:  0.8,
				Description: fmt.Sprintf("发现IP地址 %s 在 %d 个数据源中出现", ip, len(points)),
				Timestamp:   time.Now(),
			}
			result.Correlations = append(result.Correlations, correlation)
		}
	}
}

// correlateByTimeWindow 时间窗口关联分析
func (dc *DataCorrelator) correlateByTimeWindow(data []*NormalizedDataPoint, result *CorrelationResult) {
	timeWindow := 5 * time.Minute
	
	for i, point1 := range data {
		var relatedPoints []*NormalizedDataPoint
		
		for j, point2 := range data {
			if i != j && point1.Timestamp.Sub(point2.Timestamp).Abs() <= timeWindow {
				relatedPoints = append(relatedPoints, point2)
			}
		}
		
		if len(relatedPoints) > 2 {
			correlation := DataCorrelation{
				Type:        "temporal_correlation",
				Field:       "timestamp",
				Value:       point1.Timestamp.Format(time.RFC3339),
				DataPoints:  append([]*NormalizedDataPoint{point1}, relatedPoints...),
				Confidence:  0.6,
				Description: fmt.Sprintf("在时间窗口内发现 %d 个相关事件", len(relatedPoints)+1),
				Timestamp:   time.Now(),
			}
			result.Correlations = append(result.Correlations, correlation)
		}
	}
}

// correlateByUser 用户行为关联分析
func (dc *DataCorrelator) correlateByUser(data []*NormalizedDataPoint, result *CorrelationResult) {
	userGroups := make(map[string][]*NormalizedDataPoint)
	
	for _, point := range data {
		if point.User != "" {
			userGroups[point.User] = append(userGroups[point.User], point)
		}
	}
	
	for user, points := range userGroups {
		if len(points) > 1 {
			correlation := DataCorrelation{
				Type:        "user_correlation",
				Field:       "user",
				Value:       user,
				DataPoints:  points,
				Confidence:  0.7,
				Description: fmt.Sprintf("用户 %s 的活动在多个数据源中出现", user),
				Timestamp:   time.Now(),
			}
			result.Correlations = append(result.Correlations, correlation)
		}
	}
}

// detectKnownThreatPatterns 检测已知威胁模式
func (dc *DataCorrelator) detectKnownThreatPatterns(data []*NormalizedDataPoint, result *CorrelationResult) {
	// 检测端口扫描模式
	dc.detectPortScanPattern(data, result)
	
	// 检测暴力破解模式
	dc.detectBruteForcePattern(data, result)
	
	// 检测恶意软件通信模式
	dc.detectMalwareCommunicationPattern(data, result)
}

// detectPortScanPattern 检测端口扫描模式
func (dc *DataCorrelator) detectPortScanPattern(data []*NormalizedDataPoint, result *CorrelationResult) {
	ipConnections := make(map[string]int)
	
	for _, point := range data {
		if point.IPAddress != "" && strings.Contains(strings.ToLower(point.Type), "network") {
			ipConnections[point.IPAddress]++
		}
	}
	
	for ip, count := range ipConnections {
		if count > 10 { // 如果连接数超过10，可能是扫描
			pattern := ThreatPattern{
				PatternID:   fmt.Sprintf("port_scan_%s", ip),
				Type:        "port_scan",
				Name:        "端口扫描检测",
				Description: fmt.Sprintf("检测到来自 %s 的疑似端口扫描活动", ip),
				Severity:    "medium",
				Confidence:  0.7,
				Indicators:  []string{fmt.Sprintf("ip:%s", ip), fmt.Sprintf("connections:%d", count)},
				Timestamp:   time.Now(),
			}
			result.Patterns = append(result.Patterns, pattern)
		}
	}
}

// detectBruteForcePattern 检测暴力破解模式
func (dc *DataCorrelator) detectBruteForcePattern(data []*NormalizedDataPoint, result *CorrelationResult) {
	failedLogins := make(map[string]int)
	
	for _, point := range data {
		if strings.Contains(strings.ToLower(point.Type), "auth") || 
		   strings.Contains(strings.ToLower(fmt.Sprintf("%v", point.Attributes)), "failed") {
			key := fmt.Sprintf("%s:%s", point.IPAddress, point.User)
			failedLogins[key]++
		}
	}
	
	for key, count := range failedLogins {
		if count > 5 { // 失败次数超过5次
			parts := strings.Split(key, ":")
			pattern := ThreatPattern{
				PatternID:   fmt.Sprintf("brute_force_%s", key),
				Type:        "brute_force",
				Name:        "暴力破解攻击检测",
				Description: fmt.Sprintf("检测到针对用户 %s 的暴力破解攻击", parts[1]),
				Severity:    "high",
				Confidence:  0.8,
				Indicators:  []string{fmt.Sprintf("failed_attempts:%d", count)},
				Timestamp:   time.Now(),
			}
			result.Patterns = append(result.Patterns, pattern)
		}
	}
}

// detectMalwareCommunicationPattern 检测恶意软件通信模式
func (dc *DataCorrelator) detectMalwareCommunicationPattern(data []*NormalizedDataPoint, result *CorrelationResult) {
	suspiciousDomains := []string{"tor", "onion", "bit.ly", "tinyurl"}
	
	for _, point := range data {
		if point.Domain != "" {
			for _, suspicious := range suspiciousDomains {
				if strings.Contains(strings.ToLower(point.Domain), suspicious) {
					pattern := ThreatPattern{
						PatternID:   fmt.Sprintf("malware_comm_%s", point.Domain),
						Type:        "malware_communication",
						Name:        "恶意软件通信检测",
						Description: fmt.Sprintf("检测到与可疑域名 %s 的通信", point.Domain),
						Severity:    "high",
						Confidence:  0.6,
						Indicators:  []string{fmt.Sprintf("domain:%s", point.Domain)},
						Timestamp:   time.Now(),
					}
					result.Patterns = append(result.Patterns, pattern)
				}
			}
		}
	}
}

// buildTimeline 构建事件时间线
func (dc *DataCorrelator) buildTimeline(data []*NormalizedDataPoint, result *CorrelationResult) {
	// 按时间排序数据点
	sortedData := make([]*NormalizedDataPoint, len(data))
	copy(sortedData, data)
	
	// 简化的排序实现
	for i := 0; i < len(sortedData)-1; i++ {
		for j := i + 1; j < len(sortedData); j++ {
			if sortedData[i].Timestamp.After(sortedData[j].Timestamp) {
				sortedData[i], sortedData[j] = sortedData[j], sortedData[i]
			}
		}
	}
	
	// 构建时间线事件
	for _, point := range sortedData {
		event := TimelineEvent{
			Timestamp:   point.Timestamp,
			EventType:   point.Type,
			Source:      point.SourceID,
			Description: dc.generateEventDescription(point),
			Severity:    dc.inferSeverity(point),
			Details:     point.Attributes,
		}
		result.Timeline = append(result.Timeline, event)
	}
}

// detectAnomalies 检测异常
func (dc *DataCorrelator) detectAnomalies(data []*NormalizedDataPoint, result *CorrelationResult) {
	// 检测频率异常
	dc.detectFrequencyAnomalies(data, result)
	
	// 检测时间异常
	dc.detectTimeAnomalies(data, result)
	
	// 检测地理位置异常
	dc.detectGeoAnomalies(data, result)
}

// detectFrequencyAnomalies 检测频率异常
func (dc *DataCorrelator) detectFrequencyAnomalies(data []*NormalizedDataPoint, result *CorrelationResult) {
	hourlyCount := make(map[int]int)
	
	for _, point := range data {
		hour := point.Timestamp.Hour()
		hourlyCount[hour]++
	}
	
	// 计算平均值
	total := 0
	for _, count := range hourlyCount {
		total += count
	}
	average := float64(total) / 24.0
	
	// 检测异常高的活动
	for hour, count := range hourlyCount {
		if float64(count) > average*3 { // 超过平均值3倍
			anomaly := SecurityAnomaly{
				AnomalyID:   fmt.Sprintf("freq_anomaly_%d", hour),
				Type:        "frequency_anomaly",
				Description: fmt.Sprintf("在 %d 点检测到异常高的活动频率", hour),
				Severity:    "medium",
				Confidence:  0.6,
				Timestamp:   time.Now(),
				Details: map[string]interface{}{
					"hour":    hour,
					"count":   count,
					"average": average,
				},
			}
			result.Anomalies = append(result.Anomalies, anomaly)
		}
	}
}

// 辅助方法

func (dc *DataCorrelator) extractTimestamp(data map[string]interface{}) time.Time {
	if ts, ok := data["timestamp"]; ok {
		if timeStr, ok := ts.(string); ok {
			if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
				return t
			}
		}
		if t, ok := ts.(time.Time); ok {
			return t
		}
	}
	return time.Now()
}

func (dc *DataCorrelator) extractField(data map[string]interface{}, fields ...string) string {
	for _, field := range fields {
		if value, ok := data[field]; ok {
			if str, ok := value.(string); ok && str != "" {
				return str
			}
		}
	}
	return ""
}

func (dc *DataCorrelator) inferDataType(data map[string]interface{}) string {
	if _, ok := data["ip_address"]; ok {
		return "network_log"
	}
	if _, ok := data["user"]; ok {
		return "auth_log"
	}
	if _, ok := data["process"]; ok {
		return "process_log"
	}
	return "general_log"
}

func (dc *DataCorrelator) generateEventDescription(point *NormalizedDataPoint) string {
	return fmt.Sprintf("%s event from %s", point.Type, point.SourceID)
}

func (dc *DataCorrelator) inferSeverity(point *NormalizedDataPoint) string {
	desc := strings.ToLower(fmt.Sprintf("%v", point.Attributes))
	if strings.Contains(desc, "error") || strings.Contains(desc, "failed") {
		return "high"
	}
	if strings.Contains(desc, "warning") || strings.Contains(desc, "suspicious") {
		return "medium"
	}
	return "low"
}

// 其他未实现的方法存根
func (dc *DataCorrelator) correlateEventSequence(data []*NormalizedDataPoint, result *CorrelationResult)        {}
func (dc *DataCorrelator) analyzeImpactScope(data []*NormalizedDataPoint, result *CorrelationResult)           {}
func (dc *DataCorrelator) reconstructAttackChain(data []*NormalizedDataPoint, result *CorrelationResult)       {}
func (dc *DataCorrelator) correlateErrorPatterns(data []*NormalizedDataPoint, result *CorrelationResult)       {}
func (dc *DataCorrelator) analyzeFrequencyPatterns(data []*NormalizedDataPoint, result *CorrelationResult)     {}
func (dc *DataCorrelator) correlateByGeoLocation(data []*NormalizedDataPoint, result *CorrelationResult)       {}
func (dc *DataCorrelator) correlateByCommonFields(data []*NormalizedDataPoint, result *CorrelationResult)      {}
func (dc *DataCorrelator) performStatisticalAnalysis(data []*NormalizedDataPoint, result *CorrelationResult)   {}
func (dc *DataCorrelator) detectTimeAnomalies(data []*NormalizedDataPoint, result *CorrelationResult)          {}
func (dc *DataCorrelator) detectGeoAnomalies(data []*NormalizedDataPoint, result *CorrelationResult)           {}

func (dc *DataCorrelator) generateInsights(result *CorrelationResult) {
	// 生成基于关联分析的洞察
	if len(result.Correlations) > 0 {
		insight := AnalysisInsight{
			InsightID:   "correlation_summary",
			Type:        "correlation_analysis",
			Title:       "数据关联分析摘要",
			Description: fmt.Sprintf("发现 %d 个数据关联模式", len(result.Correlations)),
			Confidence:  0.7,
			Impact:      "medium",
			Timestamp:   time.Now(),
		}
		result.Insights = append(result.Insights, insight)
	}

	if len(result.Patterns) > 0 {
		insight := AnalysisInsight{
			InsightID:   "threat_pattern_summary",
			Type:        "threat_analysis",
			Title:       "威胁模式检测摘要",
			Description: fmt.Sprintf("检测到 %d 个威胁模式", len(result.Patterns)),
			Confidence:  0.8,
			Impact:      "high",
			Timestamp:   time.Now(),
		}
		result.Insights = append(result.Insights, insight)
	}
}

func (dc *DataCorrelator) calculateOverallConfidence(result *CorrelationResult) float64 {
	if len(result.Correlations) == 0 && len(result.Patterns) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	count := 0

	for _, correlation := range result.Correlations {
		totalConfidence += correlation.Confidence
		count++
	}

	for _, pattern := range result.Patterns {
		totalConfidence += pattern.Confidence
		count++
	}

	if count == 0 {
		return 0.0
	}

	return totalConfidence / float64(count)
}

// 数据结构定义

// NormalizedDataPoint 标准化数据点
type NormalizedDataPoint struct {
	SourceID   string                 `json:"source_id"`
	Type       string                 `json:"type"`
	Timestamp  time.Time              `json:"timestamp"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	Domain     string                 `json:"domain,omitempty"`
	User       string                 `json:"user,omitempty"`
	Process    string                 `json:"process,omitempty"`
	File       string                 `json:"file,omitempty"`
	Attributes map[string]interface{} `json:"attributes"`
}

// CorrelationResult 关联分析结果
type CorrelationResult struct {
	Status       string               `json:"status"`
	Intent       string               `json:"intent"`
	Correlations []DataCorrelation    `json:"correlations"`
	Patterns     []ThreatPattern      `json:"patterns"`
	Anomalies    []SecurityAnomaly    `json:"anomalies"`
	Timeline     []TimelineEvent      `json:"timeline"`
	Insights     []AnalysisInsight    `json:"insights"`
	Confidence   float64              `json:"confidence"`
	Duration     time.Duration        `json:"duration"`
	StartTime    time.Time            `json:"start_time"`
	EndTime      time.Time            `json:"end_time"`
}

// DataCorrelation 数据关联
type DataCorrelation struct {
	Type        string                 `json:"type"`
	Field       string                 `json:"field"`
	Value       string                 `json:"value"`
	DataPoints  []*NormalizedDataPoint `json:"data_points"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ThreatPattern 威胁模式
type ThreatPattern struct {
	PatternID   string    `json:"pattern_id"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Indicators  []string  `json:"indicators"`
	Timestamp   time.Time `json:"timestamp"`
}

// SecurityAnomaly 安全异常
type SecurityAnomaly struct {
	AnomalyID   string                 `json:"anomaly_id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

// TimelineEvent 时间线事件
type TimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Details     map[string]interface{} `json:"details"`
}

// AnalysisInsight 分析洞察
type AnalysisInsight struct {
	InsightID   string    `json:"insight_id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Confidence  float64   `json:"confidence"`
	Impact      string    `json:"impact"`
	Timestamp   time.Time `json:"timestamp"`
}