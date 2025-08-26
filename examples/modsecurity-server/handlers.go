package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// HandleToolCall 处理工具调用
func (s *ModSecurityServer) HandleToolCall(name string, arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	switch name {
	case "analyze_request":
		return s.handleAnalyzeRequest(arguments)
	case "block_ip":
		return s.handleBlockIP(arguments)
	case "unblock_ip":
		return s.handleUnblockIP(arguments)
	case "get_attack_logs":
		return s.handleGetAttackLogs(arguments)
	case "update_waf_config":
		return s.handleUpdateWAFConfig(arguments)
	case "create_custom_rule":
		return s.handleCreateCustomRule(arguments)
	case "test_rule":
		return s.handleTestRule(arguments)
	case "generate_report":
		return s.handleGenerateReport(arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

// ThreatAnalysis 威胁分析结果
type ThreatAnalysis struct {
	ThreatDetected    bool     `json:"threat_detected"`
	ThreatScore       float64  `json:"threat_score"`
	AttackType        string   `json:"attack_type"`
	Severity          string   `json:"severity"`
	TriggeredRule     string   `json:"triggered_rule"`
	RecommendedAction string   `json:"recommended_action"`
	ProcessingTime    int64    `json:"processing_time"`
	ResponseCode      int      `json:"response_code"`
	Risk              string   `json:"risk"`
}

// handleAnalyzeRequest 处理HTTP请求分析
func (s *ModSecurityServer) handleAnalyzeRequest(args map[string]interface{}) (*mcp.CallToolResult, error) {
	requestData, ok := args["request_data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("request_data is required")
	}

	method, _ := requestData["method"].(string)
	url, _ := requestData["url"].(string)
	body, _ := requestData["body"].(string)
	sourceIP, _ := requestData["source_ip"].(string)

	// 执行威胁分析
	analysis := s.analyzeHTTPRequest(method, url, body, sourceIP)

	// 记录攻击日志
	if analysis.ThreatDetected {
		attackLog := AttackLog{
			ID:            generateAttackID(),
			Timestamp:     time.Now(),
			SourceIP:      sourceIP,
			TargetURL:     url,
			AttackType:    analysis.AttackType,
			Severity:      analysis.Severity,
			RuleID:        analysis.TriggeredRule,
			Action:        analysis.RecommendedAction,
			RequestMethod: method,
			RequestBody:   body,
			ResponseCode:  analysis.ResponseCode,
			Blocked:       analysis.RecommendedAction == "block",
		}
		s.attackLogs = append(s.attackLogs, attackLog)
	}

	data, _ := json.Marshal(analysis)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleBlockIP 处理IP阻止
func (s *ModSecurityServer) handleBlockIP(args map[string]interface{}) (*mcp.CallToolResult, error) {
	ipAddress, ok := args["ip_address"].(string)
	if !ok {
		return nil, fmt.Errorf("ip_address is required")
	}

	reason, ok := args["reason"].(string)
	if !ok {
		return nil, fmt.Errorf("reason is required")
	}

	// 验证IP格式
	if net.ParseIP(ipAddress) == nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.TextContent{{
				Type: "text",
				Text: fmt.Sprintf("无效的IP地址格式: %s", ipAddress),
			}},
		}, nil
	}

	// 创建阻止记录
	blockedIP := BlockedIP{
		IP:        ipAddress,
		Reason:    reason,
		BlockedAt: time.Now(),
		Status:    "active",
	}
	s.blockedIPs = append(s.blockedIPs, blockedIP)

	result := map[string]interface{}{
		"status":  "success",
		"ip":      ipAddress,
		"message": fmt.Sprintf("IP %s 已被成功阻止", ipAddress),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleUnblockIP 处理IP解除阻止
func (s *ModSecurityServer) handleUnblockIP(args map[string]interface{}) (*mcp.CallToolResult, error) {
	ipAddress, ok := args["ip_address"].(string)
	if !ok {
		return nil, fmt.Errorf("ip_address is required")
	}

	// 查找并更新阻止记录
	found := false
	for i, blockedIP := range s.blockedIPs {
		if blockedIP.IP == ipAddress && blockedIP.Status == "active" {
			s.blockedIPs[i].Status = "unblocked"
			found = true
			break
		}
	}

	if !found {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.TextContent{{
				Type: "text",
				Text: fmt.Sprintf("IP未在阻止列表中: %s", ipAddress),
			}},
		}, nil
	}

	result := map[string]interface{}{
		"status":  "success",
		"ip":      ipAddress,
		"message": fmt.Sprintf("IP %s 已被成功解除阻止", ipAddress),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleGetAttackLogs 处理获取攻击日志
func (s *ModSecurityServer) handleGetAttackLogs(args map[string]interface{}) (*mcp.CallToolResult, error) {
	limit := 100
	if l, exists := args["limit"]; exists {
		if lFloat, ok := l.(float64); ok {
			limit = int(lFloat)
		}
	}

	// 限制结果数量
	logs := s.attackLogs
	if len(logs) > limit {
		logs = logs[len(logs)-limit:]
	}

	result := map[string]interface{}{
		"total_logs": len(s.attackLogs),
		"logs":       logs,
		"limit":      limit,
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleUpdateWAFConfig 处理WAF配置更新  
func (s *ModSecurityServer) handleUpdateWAFConfig(args map[string]interface{}) (*mcp.CallToolResult, error) {
	updated := false
	changes := []string{}

	// 更新模式
	if mode, exists := args["mode"]; exists {
		if modeStr, ok := mode.(string); ok {
			oldMode := s.wafConfig.Mode
			s.wafConfig.Mode = modeStr
			changes = append(changes, fmt.Sprintf("模式从 %s 更改为 %s", oldMode, modeStr))
			updated = true
		}
	}

	// 更新偏执级别
	if pl, exists := args["paranoia_level"]; exists {
		if plFloat, ok := pl.(float64); ok {
			oldLevel := s.wafConfig.ParanoiaLevel
			s.wafConfig.ParanoiaLevel = int(plFloat)
			changes = append(changes, fmt.Sprintf("偏执级别从 %d 更改为 %d", oldLevel, int(plFloat)))
			updated = true
		}
	}

	if updated {
		s.wafConfig.UpdatedAt = time.Now()
	}

	result := map[string]interface{}{
		"status":  "success",
		"updated": updated,
		"changes": changes,
		"config":  s.wafConfig,
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleCreateCustomRule 处理创建自定义规则
func (s *ModSecurityServer) handleCreateCustomRule(args map[string]interface{}) (*mcp.CallToolResult, error) {
	name, ok := args["name"].(string)
	if !ok {
		return nil, fmt.Errorf("name is required")
	}

	ruleBody, ok := args["rule_body"].(string)
	if !ok {
		return nil, fmt.Errorf("rule_body is required")
	}

	severity, ok := args["severity"].(string)
	if !ok {
		return nil, fmt.Errorf("severity is required")
	}

	action, ok := args["action"].(string)
	if !ok {
		return nil, fmt.Errorf("action is required")
	}

	// 创建新规则
	rule := WAFRule{
		ID:        generateRuleID(),
		Name:      name,
		RuleBody:  ruleBody,
		Category:  "custom",
		Severity:  severity,
		Action:    action,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		HitCount:  0,
	}

	s.wafRules = append(s.wafRules, rule)

	result := map[string]interface{}{
		"status":  "success",
		"rule_id": rule.ID,
		"rule":    rule,
		"message": fmt.Sprintf("自定义规则 %s 已成功创建", name),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleTestRule 处理测试规则
func (s *ModSecurityServer) handleTestRule(args map[string]interface{}) (*mcp.CallToolResult, error) {
	ruleID, ok := args["rule_id"].(string)
	if !ok {
		return nil, fmt.Errorf("rule_id is required")
	}

	// 查找规则
	var targetRule *WAFRule
	for _, rule := range s.wafRules {
		if rule.ID == ruleID {
			targetRule = &rule
			break
		}
	}

	if targetRule == nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.TextContent{{
				Type: "text",
				Text: fmt.Sprintf("规则未找到: %s", ruleID),
			}},
		}, nil
	}

	result := map[string]interface{}{
		"status":      "success",
		"rule_id":     ruleID,
		"rule_name":   targetRule.Name,
		"test_result": "规则测试功能需要实际的ModSecurity引擎支持",
		"message":     fmt.Sprintf("规则 %s 测试完成", targetRule.Name),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleGenerateReport 处理生成报告
func (s *ModSecurityServer) handleGenerateReport(args map[string]interface{}) (*mcp.CallToolResult, error) {
	reportType, ok := args["report_type"].(string)
	if !ok {
		return nil, fmt.Errorf("report_type is required")
	}

	format := "json"
	if f, exists := args["format"]; exists {
		if fStr, ok := f.(string); ok {
			format = fStr
		}
	}

	report := s.generateSecurityReport(reportType)

	result := map[string]interface{}{
		"status":      "success",
		"report_type": reportType,
		"format":      format,
		"report":      report,
		"generated_at": time.Now(),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// analyzeHTTPRequest 分析HTTP请求
func (s *ModSecurityServer) analyzeHTTPRequest(method, url, body, sourceIP string) ThreatAnalysis {
	startTime := time.Now()
	
	analysis := ThreatAnalysis{
		ThreatDetected:    false,
		ThreatScore:       0.0,
		ProcessingTime:    0,
		ResponseCode:      200,
		Risk:             "low",
	}

	// 简化的威胁检测逻辑
	combinedData := strings.ToLower(url + " " + body)
	
	// SQL注入检测
	sqlPatterns := []string{"' or '1'='1", "union select", "drop table", "-- "}
	for _, pattern := range sqlPatterns {
		if strings.Contains(combinedData, pattern) {
			analysis.ThreatDetected = true
			analysis.AttackType = "SQL Injection"
			analysis.Severity = "high"
			analysis.ThreatScore = 0.9
			analysis.RecommendedAction = "block"
			analysis.ResponseCode = 403
			analysis.Risk = "high"
			break
		}
	}

	// XSS检测
	if !analysis.ThreatDetected {
		xssPatterns := []string{"<script", "javascript:", "alert(", "onclick="}
		for _, pattern := range xssPatterns {
			if strings.Contains(combinedData, pattern) {
				analysis.ThreatDetected = true
				analysis.AttackType = "XSS"
				analysis.Severity = "medium"
				analysis.ThreatScore = 0.7
				analysis.RecommendedAction = "warn"
				analysis.Risk = "medium"
				break
			}
		}
	}

	analysis.ProcessingTime = time.Since(startTime).Milliseconds()
	return analysis
}

// generateSecurityReport 生成安全报告
func (s *ModSecurityServer) generateSecurityReport(reportType string) map[string]interface{} {
	report := map[string]interface{}{
		"report_type": reportType,
		"period":      "last_24h",
		"summary": map[string]interface{}{
			"total_requests": len(s.httpLogs),
			"total_attacks":  len(s.attackLogs),
			"blocked_ips":    len(s.blockedIPs),
			"active_rules":   len(s.wafRules),
		},
	}

	switch reportType {
	case "attack_summary":
		attackTypes := make(map[string]int)
		for _, attack := range s.attackLogs {
			attackTypes[attack.AttackType]++
		}
		report["attack_types"] = attackTypes

	case "top_threats":
		report["top_source_ips"] = s.getTopAttackingIPs()
		report["top_attack_types"] = s.getTopAttackTypes()
	}

	return report
}

// 辅助函数
func generateAttackID() string {
	return "attack-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func generateRuleID() string {
	return "rule-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func (s *ModSecurityServer) getTopAttackingIPs() []map[string]interface{} {
	ipCounts := make(map[string]int)
	for _, attack := range s.attackLogs {
		ipCounts[attack.SourceIP]++
	}

	var result []map[string]interface{}
	for ip, count := range ipCounts {
		result = append(result, map[string]interface{}{
			"ip":    ip,
			"count": count,
		})
	}
	return result
}

func (s *ModSecurityServer) getTopAttackTypes() []map[string]interface{} {
	typeCounts := make(map[string]int)
	for _, attack := range s.attackLogs {
		typeCounts[attack.AttackType]++
	}

	var result []map[string]interface{}
	for attackType, count := range typeCounts {
		result = append(result, map[string]interface{}{
			"type":  attackType,
			"count": count,
		})
	}
	return result
}