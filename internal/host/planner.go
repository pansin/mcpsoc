package host

import (
	"fmt"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/ai"
	"github.com/sirupsen/logrus"
)

// ExecutionPlanner 执行计划器
type ExecutionPlanner struct {
	logger *logrus.Logger
}

// NewExecutionPlanner 创建新的执行计划器
func NewExecutionPlanner(logger *logrus.Logger) *ExecutionPlanner {
	return &ExecutionPlanner{
		logger: logger,
	}
}

// GeneratePlan 生成执行计划
func (ep *ExecutionPlanner) GeneratePlan(query *OrchestratedQuery, availableTools []ai.AvailableTool) (*DetailedExecutionPlan, error) {
	ep.logger.WithFields(logrus.Fields{
		"query_id": query.ID,
		"intent":   query.Intent,
	}).Info("Generating execution plan")

	// 基于查询意图确定所需工具
	requiredTools := ep.determineRequiredTools(query, availableTools)
	if len(requiredTools) == 0 {
		return nil, fmt.Errorf("no suitable tools found for query intent: %s", query.Intent)
	}

	// 生成执行阶段
	stages := ep.generateExecutionStages(query, requiredTools)

	// 估算总执行时间
	totalTime := ep.estimateTotalExecutionTime(stages)

	plan := &DetailedExecutionPlan{
		TotalStages:   len(stages),
		EstimatedTime: totalTime,
		Stages:        stages,
		Dependencies:  make(map[string][]string),
		ResourceUsage: &ResourceEstimation{},
	}

	ep.logger.WithFields(logrus.Fields{
		"query_id":      query.ID,
		"total_stages":  len(stages),
		"estimated_time": totalTime,
	}).Info("Execution plan generated")

	return plan, nil
}

// determineRequiredTools 确定所需工具
func (ep *ExecutionPlanner) determineRequiredTools(query *OrchestratedQuery, availableTools []ai.AvailableTool) []ai.AvailableTool {
	var required []ai.AvailableTool

	// 基于查询意图选择工具
	switch query.Intent {
	case "threat_analysis":
		// 威胁分析需要日志查询、威胁情报、文件扫描等工具
		for _, tool := range availableTools {
			if ep.isRelevantForThreatAnalysis(tool) {
				required = append(required, tool)
			}
		}
	case "incident_response":
		// 事件响应需要日志查询、网络控制、隔离工具等
		for _, tool := range availableTools {
			if ep.isRelevantForIncidentResponse(tool) {
				required = append(required, tool)
			}
		}
	case "log_analysis":
		// 日志分析主要需要日志查询工具
		for _, tool := range availableTools {
			if ep.isRelevantForLogAnalysis(tool) {
				required = append(required, tool)
			}
		}
	case "vulnerability_assessment":
		// 漏洞评估需要扫描工具、配置检查工具等
		for _, tool := range availableTools {
			if ep.isRelevantForVulnerabilityAssessment(tool) {
				required = append(required, tool)
			}
		}
	default:
		// 默认情况下，选择通用的查询和分析工具
		for _, tool := range availableTools {
			if ep.isGeneralPurposeTool(tool) {
				required = append(required, tool)
			}
		}
	}

	// 限制工具数量，避免计划过于复杂
	if len(required) > 10 {
		required = required[:10]
	}

	return required
}

// generateExecutionStages 生成执行阶段
func (ep *ExecutionPlanner) generateExecutionStages(query *OrchestratedQuery, tools []ai.AvailableTool) []ExecutionStage {
	var stages []ExecutionStage

	// 阶段1: 数据收集
	dataCollectionStage := ExecutionStage{
		ID:            "data_collection",
		Name:          "数据收集",
		Type:          "parallel",
		Tools:         []ToolExecution{},
		Dependencies:  []string{},
		EstimatedTime: 30 * time.Second,
		Priority:      1,
		CanFailSafe:   true,
		RetryPolicy: &RetryPolicy{
			MaxRetries:      3,
			BackoffType:     "exponential",
			InitialDelay:    time.Second,
			MaxDelay:        10 * time.Second,
			RetryConditions: []string{"network_error", "timeout"},
		},
	}

	// 添加数据收集工具
	for _, tool := range tools {
		if ep.isDataCollectionTool(tool) {
			toolExec := ToolExecution{
				ServerID:    tool.Server,
				ToolName:    tool.Name,
				Arguments:   ep.generateToolArguments(tool, query),
				Timeout:     30 * time.Second,
				RetryCount:  3,
				Priority:    1,
				FailureMode: "continue",
			}
			dataCollectionStage.Tools = append(dataCollectionStage.Tools, toolExec)
		}
	}

	if len(dataCollectionStage.Tools) > 0 {
		stages = append(stages, dataCollectionStage)
	}

	// 阶段2: 数据分析
	analysisStage := ExecutionStage{
		ID:            "analysis",
		Name:          "数据分析",
		Type:          "sequential",
		Tools:         []ToolExecution{},
		Dependencies:  []string{"data_collection"},
		EstimatedTime: 60 * time.Second,
		Priority:      2,
		CanFailSafe:   false,
		RetryPolicy: &RetryPolicy{
			MaxRetries:      2,
			BackoffType:     "linear",
			InitialDelay:    2 * time.Second,
			MaxDelay:        10 * time.Second,
			RetryConditions: []string{"processing_error"},
		},
	}

	// 添加分析工具
	for _, tool := range tools {
		if ep.isAnalysisTool(tool) {
			toolExec := ToolExecution{
				ServerID:    tool.Server,
				ToolName:    tool.Name,
				Arguments:   ep.generateToolArguments(tool, query),
				Timeout:     60 * time.Second,
				RetryCount:  2,
				Priority:    2,
				FailureMode: "abort",
			}
			analysisStage.Tools = append(analysisStage.Tools, toolExec)
		}
	}

	if len(analysisStage.Tools) > 0 {
		stages = append(stages, analysisStage)
	}

	// 阶段3: 响应行动（如果需要）
	if query.Intent == "incident_response" {
		responseStage := ExecutionStage{
			ID:            "response",
			Name:          "响应行动",
			Type:          "sequential",
			Tools:         []ToolExecution{},
			Dependencies:  []string{"analysis"},
			EstimatedTime: 45 * time.Second,
			Priority:      3,
			CanFailSafe:   false,
			RetryPolicy: &RetryPolicy{
				MaxRetries:      1,
				BackoffType:     "fixed",
				InitialDelay:    5 * time.Second,
				MaxDelay:        5 * time.Second,
				RetryConditions: []string{"resource_busy"},
			},
		}

		// 添加响应工具
		for _, tool := range tools {
			if ep.isResponseTool(tool) {
				toolExec := ToolExecution{
					ServerID:    tool.Server,
					ToolName:    tool.Name,
					Arguments:   ep.generateToolArguments(tool, query),
					Timeout:     45 * time.Second,
					RetryCount:  1,
					Priority:    3,
					FailureMode: "abort",
				}
				responseStage.Tools = append(responseStage.Tools, toolExec)
			}
		}

		if len(responseStage.Tools) > 0 {
			stages = append(stages, responseStage)
		}
	}

	return stages
}

// 工具分类辅助方法

func (ep *ExecutionPlanner) isRelevantForThreatAnalysis(tool ai.AvailableTool) bool {
	relevantKeywords := []string{"log", "scan", "threat", "intel", "detect", "search"}
	return ep.containsAnyKeyword(tool.Name+" "+tool.Description, relevantKeywords)
}

func (ep *ExecutionPlanner) isRelevantForIncidentResponse(tool ai.AvailableTool) bool {
	relevantKeywords := []string{"log", "block", "isolate", "quarantine", "disable", "search", "trace"}
	return ep.containsAnyKeyword(tool.Name+" "+tool.Description, relevantKeywords)
}

func (ep *ExecutionPlanner) isRelevantForLogAnalysis(tool ai.AvailableTool) bool {
	relevantKeywords := []string{"log", "search", "query", "filter", "parse"}
	return ep.containsAnyKeyword(tool.Name+" "+tool.Description, relevantKeywords)
}

func (ep *ExecutionPlanner) isRelevantForVulnerabilityAssessment(tool ai.AvailableTool) bool {
	relevantKeywords := []string{"scan", "vulnerability", "assess", "check", "config", "audit"}
	return ep.containsAnyKeyword(tool.Name+" "+tool.Description, relevantKeywords)
}

func (ep *ExecutionPlanner) isGeneralPurposeTool(tool ai.AvailableTool) bool {
	generalKeywords := []string{"search", "query", "list", "get", "info"}
	return ep.containsAnyKeyword(tool.Name+" "+tool.Description, generalKeywords)
}

func (ep *ExecutionPlanner) isDataCollectionTool(tool ai.AvailableTool) bool {
	collectionKeywords := []string{"get", "list", "search", "query", "fetch", "retrieve"}
	return ep.containsAnyKeyword(tool.Name, collectionKeywords)
}

func (ep *ExecutionPlanner) isAnalysisTool(tool ai.AvailableTool) bool {
	analysisKeywords := []string{"analyze", "scan", "detect", "check", "correlate", "parse"}
	return ep.containsAnyKeyword(tool.Name, analysisKeywords)
}

func (ep *ExecutionPlanner) isResponseTool(tool ai.AvailableTool) bool {
	responseKeywords := []string{"block", "isolate", "quarantine", "disable", "remove", "delete"}
	return ep.containsAnyKeyword(tool.Name, responseKeywords)
}

func (ep *ExecutionPlanner) containsAnyKeyword(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if contains([]string{text}, keyword) {
			return true
		}
	}
	return false
}

// generateToolArguments 生成工具参数
func (ep *ExecutionPlanner) generateToolArguments(tool ai.AvailableTool, query *OrchestratedQuery) map[string]interface{} {
	args := make(map[string]interface{})

	// 从查询上下文中提取相关参数
	if query.Context != nil {
		if timeRange, ok := query.Context["time_range"]; ok {
			args["time_range"] = timeRange
		}
		if ipAddress, ok := query.Context["ip_address"]; ok {
			args["ip_address"] = ipAddress
		}
		if domain, ok := query.Context["domain"]; ok {
			args["domain"] = domain
		}
		if limit, ok := query.Context["limit"]; ok {
			args["limit"] = limit
		} else {
			args["limit"] = 100 // 默认限制
		}
	}

	// 根据工具类型添加特定参数
	switch {
	case ep.containsAnyKeyword(tool.Name, []string{"log", "search"}):
		if args["time_range"] == nil {
			args["time_range"] = "1h" // 默认1小时
		}
	case ep.containsAnyKeyword(tool.Name, []string{"scan", "detect"}):
		if args["depth"] == nil {
			args["depth"] = "standard" // 默认扫描深度
		}
	}

	return args
}

// estimateTotalExecutionTime 估算总执行时间
func (ep *ExecutionPlanner) estimateTotalExecutionTime(stages []ExecutionStage) time.Duration {
	var totalTime time.Duration

	for _, stage := range stages {
		if stage.Type == "parallel" {
			// 并行阶段取最长的工具执行时间
			maxTime := time.Duration(0)
			for _, tool := range stage.Tools {
				if tool.Timeout > maxTime {
					maxTime = tool.Timeout
				}
			}
			totalTime += maxTime
		} else {
			// 串行阶段累加所有工具执行时间
			for _, tool := range stage.Tools {
				totalTime += tool.Timeout
			}
		}
	}

	// 添加阶段间的切换开销
	if len(stages) > 1 {
		totalTime += time.Duration(len(stages)-1) * 2 * time.Second
	}

	return totalTime
}

// ResourceEstimation 资源估算
type ResourceEstimation struct {
	EstimatedMemoryMB    int `json:"estimated_memory_mb"`
	EstimatedCPUPercent  int `json:"estimated_cpu_percent"`
	EstimatedNetworkKBps int `json:"estimated_network_kbps"`
}

// PlanRiskAssessment 计划风险评估
type PlanRiskAssessment struct {
	RiskLevel       string   `json:"risk_level"`
	RiskFactors     []string `json:"risk_factors"`
	MitigationSteps []string `json:"mitigation_steps"`
}