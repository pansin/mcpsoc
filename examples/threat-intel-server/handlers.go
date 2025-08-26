package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// handleLookupIOC 处理IOC查找
func (s *ThreatIntelServer) handleLookupIOC(id interface{}, args map[string]interface{}) *mcp.JSONRPCMessage {
	iocValue, ok := args["ioc_value"].(string)
	if !ok {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidParams, "Missing ioc_value parameter", nil)
	}

	iocType := ""
	if t, exists := args["ioc_type"].(string); exists {
		iocType = t
	}

	// 查找匹配的威胁指标
	var matches []IOCMatch
	for _, indicator := range s.indicators {
		if indicator.Value == iocValue {
			if iocType == "" || indicator.Type == iocType {
				matches = append(matches, IOCMatch{
					Indicator:  indicator,
					MatchType:  "exact",
					Confidence: indicator.Confidence,
					Context: map[string]interface{}{
						"match_reason": "exact_value_match",
						"last_seen":    indicator.LastSeen,
					},
				})
			}
		} else if strings.Contains(indicator.Value, iocValue) && len(iocValue) > 3 {
			// 部分匹配（用于域名子域等情况）
			if iocType == "" || indicator.Type == iocType {
				matches = append(matches, IOCMatch{
					Indicator:  indicator,
					MatchType:  "partial",
					Confidence: indicator.Confidence * 0.7, // 降低部分匹配的置信度
					Context: map[string]interface{}{
						"match_reason": "partial_match",
						"last_seen":    indicator.LastSeen,
					},
				})
			}
		}
	}

	result := map[string]interface{}{
		"query": map[string]interface{}{
			"ioc_value": iocValue,
			"ioc_type":  iocType,
		},
		"matches":     matches,
		"match_count": len(matches),
		"timestamp":   time.Now(),
	}

	if len(matches) == 0 {
		result["status"] = "not_found"
		result["message"] = "未找到匹配的威胁指标"
	} else {
		result["status"] = "found"
		result["message"] = fmt.Sprintf("找到 %d 个匹配的威胁指标", len(matches))
	}

	toolResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("IOC查找结果: %s", result["message"]),
			},
		},
		IsError: false,
	}

	// 添加详细的JSON内容
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	toolResult.Content = append(toolResult.Content, mcp.Content{
		Type:     "text",
		Text:     string(jsonData),
		MimeType: "application/json",
	})

	return mcp.NewResponse(id, toolResult)
}

// handleBulkIOCCheck 处理批量IOC检查
func (s *ThreatIntelServer) handleBulkIOCCheck(id interface{}, args map[string]interface{}) *mcp.JSONRPCMessage {
	iocListRaw, ok := args["ioc_list"]
	if !ok {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidParams, "Missing ioc_list parameter", nil)
	}

	// 解析IOC列表
	iocListBytes, _ := json.Marshal(iocListRaw)
	var iocList []map[string]interface{}
	if err := json.Unmarshal(iocListBytes, &iocList); err != nil {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidParams, "Invalid ioc_list format", nil)
	}

	results := make([]map[string]interface{}, 0, len(iocList))
	totalMatches := 0

	for _, iocItem := range iocList {
		value, hasValue := iocItem["value"].(string)
		iocType, _ := iocItem["type"].(string)

		if !hasValue {
			continue
		}

		// 查找匹配项
		var matches []IOCMatch
		for _, indicator := range s.indicators {
			if indicator.Value == value && (iocType == "" || indicator.Type == iocType) {
				matches = append(matches, IOCMatch{
					Indicator:  indicator,
					MatchType:  "exact",
					Confidence: indicator.Confidence,
				})
			}
		}

		itemResult := map[string]interface{}{
			"ioc_value":   value,
			"ioc_type":    iocType,
			"matches":     matches,
			"match_count": len(matches),
			"is_malicious": len(matches) > 0,
		}

		if len(matches) > 0 {
			// 计算最高威胁级别
			highestConfidence := 0.0
			var threatTypes []string
			for _, match := range matches {
				if match.Confidence > highestConfidence {
					highestConfidence = match.Confidence
				}
				threatTypes = append(threatTypes, match.Indicator.ThreatTypes...)
			}
			itemResult["max_confidence"] = highestConfidence
			itemResult["threat_types"] = removeDuplicates(threatTypes)
		}

		results = append(results, itemResult)
		totalMatches += len(matches)
	}

	result := map[string]interface{}{
		"total_checked":    len(iocList),
		"total_matches":    totalMatches,
		"malicious_count":  countMalicious(results),
		"clean_count":      len(iocList) - countMalicious(results),
		"results":          results,
		"timestamp":        time.Now(),
	}

	toolResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("批量IOC检查完成: 检查了 %d 个指标，发现 %d 个威胁匹配", len(iocList), totalMatches),
			},
		},
		IsError: false,
	}

	// 添加详细结果
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	toolResult.Content = append(toolResult.Content, mcp.Content{
		Type:     "text",
		Text:     string(jsonData),
		MimeType: "application/json",
	})

	return mcp.NewResponse(id, toolResult)
}

// handleAddThreatIndicator 处理添加威胁指标
func (s *ThreatIntelServer) handleAddThreatIndicator(id interface{}, args map[string]interface{}) *mcp.JSONRPCMessage {
	indicatorType, ok := args["type"].(string)
	if !ok {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidParams, "Missing type parameter", nil)
	}

	value, ok := args["value"].(string)
	if !ok {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidParams, "Missing value parameter", nil)
	}

	// 检查是否已存在
	for _, existing := range s.indicators {
		if existing.Type == indicatorType && existing.Value == value {
			return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidRequest, "Indicator already exists", nil)
		}
	}

	// 创建新指标
	newIndicator := ThreatIndicator{
		ID:        fmt.Sprintf("ioc-%d", time.Now().Unix()),
		Type:      indicatorType,
		Value:     value,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Source:    "mcp_server",
	}

	// 设置可选参数
	if conf, ok := args["confidence"].(float64); ok {
		newIndicator.Confidence = conf
	} else {
		newIndicator.Confidence = 0.5 // 默认置信度
	}

	if desc, ok := args["description"].(string); ok {
		newIndicator.Description = desc
	}

	if source, ok := args["source"].(string); ok {
		newIndicator.Source = source
	}

	if threatTypesRaw, ok := args["threat_types"]; ok {
		if threatTypes, err := parseStringArray(threatTypesRaw); err == nil {
			newIndicator.ThreatTypes = threatTypes
		}
	}

	// 添加到内存存储
	s.indicators = append(s.indicators, newIndicator)

	result := map[string]interface{}{
		"status":    "success",
		"message":   "威胁指标添加成功",
		"indicator": newIndicator,
		"timestamp": time.Now(),
	}

	toolResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("成功添加威胁指标: %s (%s)", value, indicatorType),
			},
		},
		IsError: false,
	}

	jsonData, _ := json.MarshalIndent(result, "", "  ")
	toolResult.Content = append(toolResult.Content, mcp.Content{
		Type:     "text",
		Text:     string(jsonData),
		MimeType: "application/json",
	})

	return mcp.NewResponse(id, toolResult)
}

// handleSearchIndicators 处理指标搜索
func (s *ThreatIntelServer) handleSearchIndicators(id interface{}, args map[string]interface{}) *mcp.JSONRPCMessage {
	query, _ := args["query"].(string)
	indicatorType, _ := args["indicator_type"].(string)
	threatType, _ := args["threat_type"].(string)
	minConfidence, _ := args["min_confidence"].(float64)
	limit := 100
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	var results []ThreatIndicator
	for _, indicator := range s.indicators {
		// 应用过滤条件
		if indicatorType != "" && indicator.Type != indicatorType {
			continue
		}

		if threatType != "" {
			found := false
			for _, tt := range indicator.ThreatTypes {
				if tt == threatType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if minConfidence > 0 && indicator.Confidence < minConfidence {
			continue
		}

		if query != "" {
			queryLower := strings.ToLower(query)
			if !strings.Contains(strings.ToLower(indicator.Value), queryLower) &&
				!strings.Contains(strings.ToLower(indicator.Description), queryLower) {
				continue
			}
		}

		results = append(results, indicator)
		if len(results) >= limit {
			break
		}
	}

	result := map[string]interface{}{
		"query": map[string]interface{}{
			"search_term":     query,
			"indicator_type":  indicatorType,
			"threat_type":     threatType,
			"min_confidence":  minConfidence,
			"limit":           limit,
		},
		"results":      results,
		"result_count": len(results),
		"timestamp":    time.Now(),
	}

	toolResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("搜索完成，找到 %d 个匹配的威胁指标", len(results)),
			},
		},
		IsError: false,
	}

	jsonData, _ := json.MarshalIndent(result, "", "  ")
	toolResult.Content = append(toolResult.Content, mcp.Content{
		Type:     "text",
		Text:     string(jsonData),
		MimeType: "application/json",
	})

	return mcp.NewResponse(id, toolResult)
}

// handleUpdateThreatFeeds 处理威胁情报源更新
func (s *ThreatIntelServer) handleUpdateThreatFeeds(id interface{}, args map[string]interface{}) *mcp.JSONRPCMessage {
	feedID, _ := args["feed_id"].(string)
	force, _ := args["force"].(bool)

	var updatedFeeds []ThreatFeed
	var newIndicatorsCount int

	for i, feed := range s.feeds {
		if feedID != "" && feed.ID != feedID {
			continue
		}

		if !force && time.Since(feed.LastUpdate) < time.Hour {
			continue // 跳过最近更新的源
		}

		// 模拟更新过程
		s.feeds[i].LastUpdate = time.Now()
		updatedFeeds = append(updatedFeeds, s.feeds[i])

		// 模拟添加新指标
		mockNewIndicators := s.generateMockIndicators(feed.ID, 2)
		s.indicators = append(s.indicators, mockNewIndicators...)
		newIndicatorsCount += len(mockNewIndicators)
	}

	result := map[string]interface{}{
		"status":              "completed",
		"updated_feeds":       updatedFeeds,
		"updated_feed_count":  len(updatedFeeds),
		"new_indicators":      newIndicatorsCount,
		"timestamp":           time.Now(),
	}

	toolResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("威胁情报源更新完成: 更新了 %d 个情报源，新增 %d 个威胁指标", len(updatedFeeds), newIndicatorsCount),
			},
		},
		IsError: false,
	}

	jsonData, _ := json.MarshalIndent(result, "", "  ")
	toolResult.Content = append(toolResult.Content, mcp.Content{
		Type:     "text",
		Text:     string(jsonData),
		MimeType: "application/json",
	})

	return mcp.NewResponse(id, toolResult)
}

// handleGetIOCContext 处理获取IOC上下文
func (s *ThreatIntelServer) handleGetIOCContext(id interface{}, args map[string]interface{}) *mcp.JSONRPCMessage {
	iocValue, ok := args["ioc_value"].(string)
	if !ok {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidParams, "Missing ioc_value parameter", nil)
	}

	includeRelated, _ := args["include_related"].(bool)
	includeCampaigns, _ := args["include_campaigns"].(bool)

	// 找到主要指标
	var mainIndicator *ThreatIndicator
	for _, indicator := range s.indicators {
		if indicator.Value == iocValue {
			mainIndicator = &indicator
			break
		}
	}

	if mainIndicator == nil {
		return mcp.NewErrorResponse(id, mcp.ErrorCodeInvalidRequest, "IOC not found", nil)
	}

	context := map[string]interface{}{
		"primary_indicator": mainIndicator,
		"context_timestamp": time.Now(),
	}

	if includeRelated {
		// 查找相关指标
		var relatedIndicators []ThreatIndicator
		for _, indicator := range s.indicators {
			if indicator.Value != iocValue {
				// 检查是否有共同的威胁类型
				for _, tt1 := range mainIndicator.ThreatTypes {
					for _, tt2 := range indicator.ThreatTypes {
						if tt1 == tt2 {
							relatedIndicators = append(relatedIndicators, indicator)
							goto nextIndicator
						}
					}
				}
			}
		nextIndicator:
		}
		context["related_indicators"] = relatedIndicators
	}

	if includeCampaigns {
		// 模拟关联活动信息
		campaigns := []map[string]interface{}{
			{
				"name":        "APT-2024-001",
				"description": "模拟APT活动",
				"first_seen":  time.Now().Add(-30 * 24 * time.Hour),
				"last_seen":   time.Now().Add(-2 * 24 * time.Hour),
				"confidence":  0.8,
			},
		}
		context["campaigns"] = campaigns
	}

	toolResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("获取IOC上下文信息: %s", iocValue),
			},
		},
		IsError: false,
	}

	jsonData, _ := json.MarshalIndent(context, "", "  ")
	toolResult.Content = append(toolResult.Content, mcp.Content{
		Type:     "text",
		Text:     string(jsonData),
		MimeType: "application/json",
	})

	return mcp.NewResponse(id, toolResult)
}

// 辅助函数

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func countMalicious(results []map[string]interface{}) int {
	count := 0
	for _, result := range results {
		if malicious, ok := result["is_malicious"].(bool); ok && malicious {
			count++
		}
	}
	return count
}

func parseStringArray(raw interface{}) ([]string, error) {
	bytes, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	var result []string
	err = json.Unmarshal(bytes, &result)
	return result, err
}

func (s *ThreatIntelServer) generateMockIndicators(feedID string, count int) []ThreatIndicator {
	var indicators []ThreatIndicator
	
	mockData := []struct {
		Type        string
		Value       string
		ThreatTypes []string
		Description string
	}{
		{"ip", "203.0.113.10", []string{"malware"}, "恶意IP地址"},
		{"domain", "malicious.example.org", []string{"phishing"}, "钓鱼域名"},
		{"hash", "5d41402abc4b2a76b9719d911017c592", []string{"trojan"}, "木马文件哈希"},
		{"url", "http://evil.example.net/payload", []string{"malware", "c2"}, "恶意URL"},
	}

	for i := 0; i < count && i < len(mockData); i++ {
		data := mockData[i]
		indicator := ThreatIndicator{
			ID:          fmt.Sprintf("ioc-%s-%d", feedID, time.Now().UnixNano()+int64(i)),
			Type:        data.Type,
			Value:       data.Value,
			Confidence:  0.7 + float64(i)*0.1,
			ThreatTypes: data.ThreatTypes,
			Source:      feedID,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Description: data.Description,
			Tags:        []string{"auto_imported", feedID},
		}
		indicators = append(indicators, indicator)
	}

	return indicators
}