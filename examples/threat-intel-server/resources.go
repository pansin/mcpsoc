package main

import (
	"encoding/json"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// handleListResources 处理资源列表请求
func (s *ThreatIntelServer) handleListResources(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"resources": s.resources,
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleReadResource 处理资源读取请求
func (s *ThreatIntelServer) handleReadResource(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	var req map[string]interface{}
	if err := json.Unmarshal(msg.Params.([]byte), &req); err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Invalid parameters", nil)
	}

	uri, ok := req["uri"].(string)
	if !ok {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Missing uri parameter", nil)
	}

	switch uri {
	case "threat-intel://indicators/all":
		return s.handleAllIndicatorsResource(msg.ID)
	case "threat-intel://feeds/status":
		return s.handleFeedsStatusResource(msg.ID)
	case "threat-intel://statistics/summary":
		return s.handleStatisticsSummaryResource(msg.ID)
	case "threat-intel://export/stix":
		return s.handleSTIXExportResource(msg.ID)
	default:
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidRequest, "Unknown resource URI", nil)
	}
}

// handleAllIndicatorsResource 处理所有指标资源
func (s *ThreatIntelServer) handleAllIndicatorsResource(id interface{}) *mcp.JSONRPCMessage {
	data := map[string]interface{}{
		"indicators":     s.indicators,
		"total_count":    len(s.indicators),
		"generated_at":   time.Now(),
		"resource_type":  "threat_indicators",
	}

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	
	result := &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "text",
				Text:     string(jsonData),
				MimeType: "application/json",
			},
		},
	}

	return mcp.NewResponse(id, result)
}

// handleFeedsStatusResource 处理情报源状态资源
func (s *ThreatIntelServer) handleFeedsStatusResource(id interface{}) *mcp.JSONRPCMessage {
	feedsStatus := make([]map[string]interface{}, 0, len(s.feeds))
	
	for _, feed := range s.feeds {
		status := map[string]interface{}{
			"id":               feed.ID,
			"name":             feed.Name,
			"type":             feed.Type,
			"url":              feed.URL,
			"is_active":        feed.IsActive,
			"last_update":      feed.LastUpdate,
			"update_interval":  "4h", // 模拟更新间隔
		}

		// 计算状态
		timeSinceUpdate := time.Since(feed.LastUpdate)
		if timeSinceUpdate > 24*time.Hour {
			status["health_status"] = "stale"
		} else if timeSinceUpdate > 6*time.Hour {
			status["health_status"] = "warning"
		} else {
			status["health_status"] = "healthy"
		}

		// 模拟指标统计
		indicatorCount := 0
		for _, indicator := range s.indicators {
			if indicator.Source == feed.ID {
				indicatorCount++
			}
		}
		status["indicator_count"] = indicatorCount

		feedsStatus = append(feedsStatus, status)
	}

	data := map[string]interface{}{
		"feeds":          feedsStatus,
		"total_feeds":    len(s.feeds),
		"active_feeds":   s.countActiveFeeds(),
		"last_check":     time.Now(),
		"resource_type":  "feeds_status",
	}

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	
	result := &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "text",
				Text:     string(jsonData),
				MimeType: "application/json",
			},
		},
	}

	return mcp.NewResponse(id, result)
}

// handleStatisticsSummaryResource 处理统计摘要资源
func (s *ThreatIntelServer) handleStatisticsSummaryResource(id interface{}) *mcp.JSONRPCMessage {
	// 计算各种统计信息
	stats := map[string]interface{}{
		"total_indicators":   len(s.indicators),
		"indicator_by_type":  s.getIndicatorsByType(),
		"threat_type_stats":  s.getThreatTypeStats(),
		"confidence_stats":   s.getConfidenceStats(),
		"source_stats":       s.getSourceStats(),
		"recent_indicators":  s.getRecentIndicatorsCount(24 * time.Hour),
		"high_confidence":    s.getHighConfidenceCount(0.8),
		"generated_at":       time.Now(),
		"resource_type":      "statistics_summary",
	}

	jsonData, _ := json.MarshalIndent(stats, "", "  ")
	
	result := &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "text",
				Text:     string(jsonData),
				MimeType: "application/json",
			},
		},
	}

	return mcp.NewResponse(id, result)
}

// handleSTIXExportResource 处理STIX导出资源
func (s *ThreatIntelServer) handleSTIXExportResource(id interface{}) *mcp.JSONRPCMessage {
	// 创建简化的STIX 2.1格式数据
	stixBundle := map[string]interface{}{
		"type":    "bundle",
		"id":      "bundle--" + generateUUID(),
		"objects": []map[string]interface{}{},
	}

	// 添加身份对象
	identity := map[string]interface{}{
		"type":         "identity",
		"id":           "identity--" + generateUUID(),
		"created":      time.Now().Format(time.RFC3339),
		"modified":     time.Now().Format(time.RFC3339),
		"name":         "MCPSoc Threat Intelligence Server",
		"identity_class": "organization",
	}
	stixBundle["objects"] = append(stixBundle["objects"].([]map[string]interface{}), identity)

	// 转换威胁指标为STIX格式
	for _, indicator := range s.indicators {
		stixIndicator := s.convertToSTIX(indicator, identity["id"].(string))
		stixBundle["objects"] = append(stixBundle["objects"].([]map[string]interface{}), stixIndicator)
	}

	jsonData, _ := json.MarshalIndent(stixBundle, "", "  ")
	
	result := &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "text",
				Text:     string(jsonData),
				MimeType: "application/stix+json",
			},
		},
	}

	return mcp.NewResponse(id, result)
}

// 辅助统计方法

func (s *ThreatIntelServer) countActiveFeeds() int {
	count := 0
	for _, feed := range s.feeds {
		if feed.IsActive {
			count++
		}
	}
	return count
}

func (s *ThreatIntelServer) getIndicatorsByType() map[string]int {
	stats := make(map[string]int)
	for _, indicator := range s.indicators {
		stats[indicator.Type]++
	}
	return stats
}

func (s *ThreatIntelServer) getThreatTypeStats() map[string]int {
	stats := make(map[string]int)
	for _, indicator := range s.indicators {
		for _, threatType := range indicator.ThreatTypes {
			stats[threatType]++
		}
	}
	return stats
}

func (s *ThreatIntelServer) getConfidenceStats() map[string]interface{} {
	if len(s.indicators) == 0 {
		return map[string]interface{}{
			"min": 0.0,
			"max": 0.0,
			"avg": 0.0,
		}
	}

	min := s.indicators[0].Confidence
	max := s.indicators[0].Confidence
	sum := 0.0

	for _, indicator := range s.indicators {
		if indicator.Confidence < min {
			min = indicator.Confidence
		}
		if indicator.Confidence > max {
			max = indicator.Confidence
		}
		sum += indicator.Confidence
	}

	return map[string]interface{}{
		"min": min,
		"max": max,
		"avg": sum / float64(len(s.indicators)),
	}
}

func (s *ThreatIntelServer) getSourceStats() map[string]int {
	stats := make(map[string]int)
	for _, indicator := range s.indicators {
		stats[indicator.Source]++
	}
	return stats
}

func (s *ThreatIntelServer) getRecentIndicatorsCount(duration time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-duration)
	for _, indicator := range s.indicators {
		if indicator.FirstSeen.After(cutoff) {
			count++
		}
	}
	return count
}

func (s *ThreatIntelServer) getHighConfidenceCount(threshold float64) int {
	count := 0
	for _, indicator := range s.indicators {
		if indicator.Confidence >= threshold {
			count++
		}
	}
	return count
}

// convertToSTIX 转换威胁指标为STIX格式
func (s *ThreatIntelServer) convertToSTIX(indicator ThreatIndicator, createdBy string) map[string]interface{} {
	stixIndicator := map[string]interface{}{
		"type":       "indicator",
		"id":         "indicator--" + generateUUID(),
		"created":    indicator.FirstSeen.Format(time.RFC3339),
		"modified":   indicator.LastSeen.Format(time.RFC3339),
		"created_by_ref": createdBy,
		"labels":     indicator.ThreatTypes,
		"confidence": int(indicator.Confidence * 100),
	}

	// 根据指标类型设置pattern
	var pattern string
	switch indicator.Type {
	case "ip":
		pattern = fmt.Sprintf("[network-traffic:src_ref.value = '%s']", indicator.Value)
	case "domain":
		pattern = fmt.Sprintf("[domain-name:value = '%s']", indicator.Value)
	case "hash":
		pattern = fmt.Sprintf("[file:hashes.MD5 = '%s']", indicator.Value)
	case "url":
		pattern = fmt.Sprintf("[url:value = '%s']", indicator.Value)
	case "email":
		pattern = fmt.Sprintf("[email-addr:value = '%s']", indicator.Value)
	default:
		pattern = fmt.Sprintf("[x-custom:value = '%s']", indicator.Value)
	}

	stixIndicator["pattern"] = pattern
	stixIndicator["valid_from"] = indicator.FirstSeen.Format(time.RFC3339)

	if indicator.Description != "" {
		stixIndicator["description"] = indicator.Description
	}

	return stixIndicator
}

// generateUUID 生成简单的UUID（实际项目中应使用专门的UUID库）
func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}