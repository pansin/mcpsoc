package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
	"github.com/sirupsen/logrus"
)

// ToolTranslator MCP工具调用转换器
type ToolTranslator struct {
	mcpManager *mcp.Manager
	logger     *logrus.Logger
}

// NewToolTranslator 创建新的工具转换器
func NewToolTranslator(mcpManager *mcp.Manager, logger *logrus.Logger) *ToolTranslator {
	return &ToolTranslator{
		mcpManager: mcpManager,
		logger:     logger,
	}
}

// ExecutionResult 执行结果
type ExecutionResult struct {
	ToolCall    ToolCall               `json:"tool_call"`
	Success     bool                   `json:"success"`
	Result      interface{}            `json:"result"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
}

// AggregatedResult 聚合结果
type AggregatedResult struct {
	Query           string            `json:"query"`
	Intent          string            `json:"intent"`
	TotalDuration   time.Duration     `json:"total_duration"`
	SuccessCount    int               `json:"success_count"`
	ErrorCount      int               `json:"error_count"`
	Results         []ExecutionResult `json:"results"`
	Summary         interface{}       `json:"summary"`
	Recommendations []string          `json:"recommendations"`
}

// ExecuteQuery 执行解析后的查询
func (tt *ToolTranslator) ExecuteQuery(ctx context.Context, parsedQuery *ParsedQuery) (*AggregatedResult, error) {
	tt.logger.WithFields(logrus.Fields{
		"intent":      parsedQuery.Intent,
		"tool_calls":  len(parsedQuery.ToolCalls),
		"confidence":  parsedQuery.Confidence,
	}).Info("Executing parsed query")

	startTime := time.Now()
	result := &AggregatedResult{
		Intent:          parsedQuery.Intent,
		Results:         make([]ExecutionResult, 0, len(parsedQuery.ToolCalls)),
		Recommendations: []string{},
	}

	// 根据执行计划执行工具调用
	if err := tt.executeWithPlan(ctx, parsedQuery, result); err != nil {
		return nil, fmt.Errorf("failed to execute query plan: %w", err)
	}

	result.TotalDuration = time.Since(startTime)
	result.SuccessCount = tt.countSuccesses(result.Results)
	result.ErrorCount = len(result.Results) - result.SuccessCount

	// 生成汇总和建议
	if err := tt.generateSummary(result, parsedQuery); err != nil {
		tt.logger.WithError(err).Warn("Failed to generate summary")
	}

	return result, nil
}

// executeWithPlan 根据执行计划执行工具调用
func (tt *ToolTranslator) executeWithPlan(ctx context.Context, parsedQuery *ParsedQuery, result *AggregatedResult) error {
	plan := parsedQuery.ExecutionPlan

	// 首先执行并行任务
	if len(plan.Parallel) > 0 {
		if err := tt.executeParallel(ctx, parsedQuery, plan.Parallel, result); err != nil {
			return fmt.Errorf("parallel execution failed: %w", err)
		}
	}

	// 然后按顺序执行串行任务组
	for _, group := range plan.Sequential {
		if err := tt.executeSequential(ctx, parsedQuery, group, result); err != nil {
			return fmt.Errorf("sequential execution failed: %w", err)
		}
	}

	// 如果没有明确的执行计划，按顺序执行所有工具
	if len(plan.Parallel) == 0 && len(plan.Sequential) == 0 {
		allTools := make([]string, len(parsedQuery.ToolCalls))
		for i, call := range parsedQuery.ToolCalls {
			allTools[i] = call.Tool
		}
		return tt.executeSequential(ctx, parsedQuery, allTools, result)
	}

	return nil
}

// executeParallel 并行执行工具调用
func (tt *ToolTranslator) executeParallel(ctx context.Context, parsedQuery *ParsedQuery, toolNames []string, result *AggregatedResult) error {
	var wg sync.WaitGroup
	resultsChan := make(chan ExecutionResult, len(toolNames))
	
	for _, toolName := range toolNames {
		// 查找对应的工具调用
		toolCall := tt.findToolCall(parsedQuery.ToolCalls, toolName)
		if toolCall == nil {
			continue
		}

		wg.Add(1)
		go func(tc ToolCall) {
			defer wg.Done()
			
			execResult := tt.executeSingleTool(ctx, tc)
			resultsChan <- execResult
		}(*toolCall)
	}

	wg.Wait()
	close(resultsChan)

	// 收集结果
	for execResult := range resultsChan {
		result.Results = append(result.Results, execResult)
	}

	return nil
}

// executeSequential 顺序执行工具调用
func (tt *ToolTranslator) executeSequential(ctx context.Context, parsedQuery *ParsedQuery, toolNames []string, result *AggregatedResult) error {
	for _, toolName := range toolNames {
		toolCall := tt.findToolCall(parsedQuery.ToolCalls, toolName)
		if toolCall == nil {
			continue
		}

		execResult := tt.executeSingleTool(ctx, *toolCall)
		result.Results = append(result.Results, execResult)

		// 如果是关键工具调用失败，可能需要中断执行
		if !execResult.Success && tt.isCriticalTool(toolCall.Tool) {
			tt.logger.WithField("tool", toolCall.Tool).Warn("Critical tool execution failed")
		}
	}

	return nil
}

// executeSingleTool 执行单个工具调用
func (tt *ToolTranslator) executeSingleTool(ctx context.Context, toolCall ToolCall) ExecutionResult {
	startTime := time.Now()
	
	result := ExecutionResult{
		ToolCall:  toolCall,
		Timestamp: startTime,
	}

	tt.logger.WithFields(logrus.Fields{
		"tool":   toolCall.Tool,
		"server": toolCall.Server,
	}).Debug("Executing tool call")

	// 调用MCP管理器执行工具
	mcpResult, err := tt.mcpManager.CallTool(ctx, toolCall.Server, toolCall.Tool, toolCall.Arguments)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		tt.logger.WithError(err).WithField("tool", toolCall.Tool).Error("Tool execution failed")
	} else {
		result.Success = true
		result.Result = mcpResult
	}

	result.Duration = time.Since(startTime)
	return result
}

// findToolCall 查找指定名称的工具调用
func (tt *ToolTranslator) findToolCall(toolCalls []ToolCall, toolName string) *ToolCall {
	for _, call := range toolCalls {
		if call.Tool == toolName {
			return &call
		}
	}
	return nil
}

// isCriticalTool 判断是否为关键工具
func (tt *ToolTranslator) isCriticalTool(toolName string) bool {
	criticalTools := map[string]bool{
		"get_firewall_logs":    true,
		"search_indicators":    true,
		"get_system_status":    true,
		"get_active_threats":   true,
	}
	
	return criticalTools[toolName]
}

// countSuccesses 统计成功的执行结果数量
func (tt *ToolTranslator) countSuccesses(results []ExecutionResult) int {
	count := 0
	for _, result := range results {
		if result.Success {
			count++
		}
	}
	return count
}

// generateSummary 生成汇总和建议
func (tt *ToolTranslator) generateSummary(result *AggregatedResult, parsedQuery *ParsedQuery) error {
	summary := make(map[string]interface{})
	
	// 基础统计信息
	summary["total_tools_executed"] = len(result.Results)
	summary["successful_executions"] = result.SuccessCount
	summary["failed_executions"] = result.ErrorCount
	summary["execution_time"] = result.TotalDuration.String()
	
	// 按工具类型分类结果
	summary["results_by_category"] = tt.categorizeResults(result.Results)
	
	// 根据意图生成特定摘要
	switch parsedQuery.Intent {
	case "threat_analysis":
		summary["threat_summary"] = tt.generateThreatSummary(result.Results)
	case "log_analysis":
		summary["log_summary"] = tt.generateLogSummary(result.Results)
	case "monitoring":
		summary["monitoring_summary"] = tt.generateMonitoringSummary(result.Results)
	}
	
	result.Summary = summary
	
	// 生成建议
	result.Recommendations = tt.generateRecommendations(result.Results, parsedQuery)
	
	return nil
}

// categorizeResults 按类别分类结果
func (tt *ToolTranslator) categorizeResults(results []ExecutionResult) map[string]interface{} {
	categories := make(map[string][]ExecutionResult)
	
	for _, result := range results {
		category := tt.getToolCategory(result.ToolCall.Tool)
		categories[category] = append(categories[category], result)
	}
	
	summary := make(map[string]interface{})
	for category, categoryResults := range categories {
		successCount := 0
		for _, r := range categoryResults {
			if r.Success {
				successCount++
			}
		}
		
		summary[category] = map[string]interface{}{
			"total":   len(categoryResults),
			"success": successCount,
			"failed":  len(categoryResults) - successCount,
		}
	}
	
	return summary
}

// getToolCategory 获取工具类别
func (tt *ToolTranslator) getToolCategory(toolName string) string {
	categoryMap := map[string]string{
		"get_firewall_logs":     "network_security",
		"block_ip":              "network_security",
		"get_attack_logs":       "web_security",
		"scan_file":             "endpoint_security",
		"search_indicators":     "threat_intelligence",
		"get_system_status":     "monitoring",
		"get_active_threats":    "threat_detection",
	}
	
	if category, exists := categoryMap[toolName]; exists {
		return category
	}
	
	return "general"
}

// generateThreatSummary 生成威胁分析摘要
func (tt *ToolTranslator) generateThreatSummary(results []ExecutionResult) map[string]interface{} {
	summary := make(map[string]interface{})
	
	var totalThreats int
	var highSeverityThreats int
	var blockedConnections int
	
	for _, result := range results {
		if !result.Success {
			continue
		}
		
		// 解析结果中的威胁信息
		if data, ok := result.Result.(map[string]interface{}); ok {
			if threats, exists := data["threats"]; exists {
				if threatList, ok := threats.([]interface{}); ok {
					totalThreats += len(threatList)
					// 统计高严重性威胁
					for _, threat := range threatList {
						if threatMap, ok := threat.(map[string]interface{}); ok {
							if severity, exists := threatMap["severity"]; exists {
								if severity == "high" || severity == "critical" {
									highSeverityThreats++
								}
							}
						}
					}
				}
			}
			
			if blocked, exists := data["blocked_connections"]; exists {
				if count, ok := blocked.(int); ok {
					blockedConnections += count
				}
			}
		}
	}
	
	summary["total_threats_detected"] = totalThreats
	summary["high_severity_threats"] = highSeverityThreats
	summary["blocked_connections"] = blockedConnections
	summary["threat_level"] = tt.calculateThreatLevel(highSeverityThreats, totalThreats)
	
	return summary
}

// generateLogSummary 生成日志分析摘要
func (tt *ToolTranslator) generateLogSummary(results []ExecutionResult) map[string]interface{} {
	summary := make(map[string]interface{})
	
	var totalLogs int
	var anomalousEvents int
	var sources []string
	
	for _, result := range results {
		if !result.Success {
			continue
		}
		
		if data, ok := result.Result.(map[string]interface{}); ok {
			if logs, exists := data["logs"]; exists {
				if logList, ok := logs.([]interface{}); ok {
					totalLogs += len(logList)
				}
			}
			
			if events, exists := data["anomalous_events"]; exists {
				if eventList, ok := events.([]interface{}); ok {
					anomalousEvents += len(eventList)
				}
			}
			
			if source, exists := data["source"]; exists {
				if sourceStr, ok := source.(string); ok {
					sources = append(sources, sourceStr)
				}
			}
		}
	}
	
	summary["total_logs_analyzed"] = totalLogs
	summary["anomalous_events"] = anomalousEvents
	summary["data_sources"] = sources
	summary["anomaly_rate"] = tt.calculateAnomalyRate(anomalousEvents, totalLogs)
	
	return summary
}

// generateMonitoringSummary 生成监控摘要
func (tt *ToolTranslator) generateMonitoringSummary(results []ExecutionResult) map[string]interface{} {
	summary := make(map[string]interface{})
	
	var systemsChecked int
	var healthySystems int
	var alerts int
	
	for _, result := range results {
		if !result.Success {
			continue
		}
		
		if data, ok := result.Result.(map[string]interface{}); ok {
			if systems, exists := data["systems"]; exists {
				if systemList, ok := systems.([]interface{}); ok {
					systemsChecked += len(systemList)
					
					for _, system := range systemList {
						if systemMap, ok := system.(map[string]interface{}); ok {
							if status, exists := systemMap["status"]; exists {
								if status == "healthy" || status == "normal" {
									healthySystems++
								}
							}
						}
					}
				}
			}
			
			if alertCount, exists := data["active_alerts"]; exists {
				if count, ok := alertCount.(int); ok {
					alerts += count
				}
			}
		}
	}
	
	summary["systems_checked"] = systemsChecked
	summary["healthy_systems"] = healthySystems
	summary["systems_with_issues"] = systemsChecked - healthySystems
	summary["active_alerts"] = alerts
	summary["overall_health"] = tt.calculateOverallHealth(healthySystems, systemsChecked)
	
	return summary
}

// generateRecommendations 生成建议
func (tt *ToolTranslator) generateRecommendations(results []ExecutionResult, parsedQuery *ParsedQuery) []string {
	var recommendations []string
	
	// 基于执行结果生成建议
	failedCount := 0
	for _, result := range results {
		if !result.Success {
			failedCount++
		}
	}
	
	if failedCount > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("有%d个工具调用失败，建议检查MCP服务器连接状态", failedCount))
	}
	
	// 基于意图生成特定建议
	switch parsedQuery.Intent {
	case "threat_analysis":
		recommendations = append(recommendations, "建议定期更新威胁情报源")
		recommendations = append(recommendations, "考虑增强端点检测能力")
	case "log_analysis":
		recommendations = append(recommendations, "建议优化日志收集配置")
		recommendations = append(recommendations, "考虑部署日志分析自动化规则")
	case "monitoring":
		recommendations = append(recommendations, "建议设置关键系统的实时监控告警")
		recommendations = append(recommendations, "考虑实施预防性维护计划")
	}
	
	return recommendations
}

// 辅助函数
func (tt *ToolTranslator) calculateThreatLevel(highSeverity, total int) string {
	if total == 0 {
		return "low"
	}
	
	ratio := float64(highSeverity) / float64(total)
	if ratio > 0.5 {
		return "critical"
	} else if ratio > 0.2 {
		return "high" 
	} else if ratio > 0.1 {
		return "medium"
	}
	return "low"
}

func (tt *ToolTranslator) calculateAnomalyRate(anomalous, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(anomalous) / float64(total)
}

func (tt *ToolTranslator) calculateOverallHealth(healthy, total int) string {
	if total == 0 {
		return "unknown"
	}
	
	ratio := float64(healthy) / float64(total)
	if ratio >= 0.9 {
		return "excellent"
	} else if ratio >= 0.7 {
		return "good"
	} else if ratio >= 0.5 {
		return "fair"
	}
	return "poor"
}