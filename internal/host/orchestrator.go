package host

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/ai"
	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/sirupsen/logrus"
)

// Orchestrator MCP Host智能编排器
type Orchestrator struct {
	logger        *logrus.Logger
	mcpManager    *mcp.Manager
	aiService     ai.Service
	planner       *ExecutionPlanner
	executor      *ParallelExecutor
	correlator    *DataCorrelator
	cache         *ResultCache
	metrics       *OrchestratorMetrics
	mu            sync.RWMutex
}

// NewOrchestrator 创建新的智能编排器
func NewOrchestrator(logger *logrus.Logger, mcpManager *mcp.Manager, aiService ai.Service) *Orchestrator {
	return &Orchestrator{
		logger:     logger,
		mcpManager: mcpManager,
		aiService:  aiService,
		planner:    NewExecutionPlanner(logger),
		executor:   NewParallelExecutor(mcpManager, logger),
		correlator: NewDataCorrelator(logger),
		cache:      NewResultCache(logger),
		metrics:    NewOrchestratorMetrics(),
	}
}

// OrchestratedQuery 编排查询请求
type OrchestratedQuery struct {
	ID          string                 `json:"id"`
	Query       string                 `json:"query"`
	Intent      string                 `json:"intent"`
	Priority    string                 `json:"priority"`
	Context     map[string]interface{} `json:"context"`
	Constraints *QueryConstraints      `json:"constraints"`
	SessionID   string                 `json:"session_id"`
	UserID      string                 `json:"user_id"`
	Timestamp   time.Time              `json:"timestamp"`
}

// QueryConstraints 查询约束条件
type QueryConstraints struct {
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	MaxConcurrency   int           `json:"max_concurrency"`
	RequiredSources  []string      `json:"required_sources"`
	ExcludedSources  []string      `json:"excluded_sources"`
	MinConfidence    float64       `json:"min_confidence"`
	CachingEnabled   bool          `json:"caching_enabled"`
}

// OrchestratedResult 编排执行结果
type OrchestratedResult struct {
	QueryID         string                  `json:"query_id"`
	Status          string                  `json:"status"`
	Intent          string                  `json:"intent"`
	ExecutionPlan   *DetailedExecutionPlan  `json:"execution_plan"`
	Results         *EnhancedResults        `json:"results"`
	CorrelatedData  *CorrelationResult      `json:"correlated_data"`
	Recommendations *IntelligentRecommendations `json:"recommendations"`
	Metrics         *QueryMetrics           `json:"metrics"`
	CacheInfo       *CacheInfo              `json:"cache_info"`
	Timestamp       time.Time               `json:"timestamp"`
}

// DetailedExecutionPlan 详细执行计划
type DetailedExecutionPlan struct {
	TotalStages      int                    `json:"total_stages"`
	EstimatedTime    time.Duration          `json:"estimated_time"`
	Stages           []ExecutionStage       `json:"stages"`
	Dependencies     map[string][]string    `json:"dependencies"`
	ResourceUsage    *ResourceEstimation    `json:"resource_usage"`
	RiskAssessment   *PlanRiskAssessment    `json:"risk_assessment"`
}

// ExecutionStage 执行阶段
type ExecutionStage struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Tools         []ToolExecution   `json:"tools"`
	Dependencies  []string          `json:"dependencies"`
	EstimatedTime time.Duration     `json:"estimated_time"`
	Priority      int               `json:"priority"`
	CanFailSafe   bool              `json:"can_fail_safe"`
	RetryPolicy   *RetryPolicy      `json:"retry_policy"`
}

// ToolExecution 工具执行配置
type ToolExecution struct {
	ServerID     string                 `json:"server_id"`
	ToolName     string                 `json:"tool_name"`
	Arguments    map[string]interface{} `json:"arguments"`
	Timeout      time.Duration          `json:"timeout"`
	RetryCount   int                    `json:"retry_count"`
	CacheKey     string                 `json:"cache_key"`
	Priority     int                    `json:"priority"`
	FailureMode  string                 `json:"failure_mode"` // continue, abort, retry
}

// RetryPolicy 重试策略
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	BackoffType   string        `json:"backoff_type"`   // linear, exponential, fixed
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	RetryConditions []string    `json:"retry_conditions"`
}

// ProcessQuery 处理编排查询
func (o *Orchestrator) ProcessQuery(ctx context.Context, query *OrchestratedQuery) (*OrchestratedResult, error) {
	startTime := time.Now()
	o.metrics.IncrementQueryCount()

	o.logger.WithFields(logrus.Fields{
		"query_id": query.ID,
		"intent":   query.Intent,
		"priority": query.Priority,
	}).Info("Processing orchestrated query")

	// 检查缓存
	if query.Constraints != nil && query.Constraints.CachingEnabled {
		if cached := o.cache.Get(query.Query, query.Context); cached != nil {
			o.logger.WithField("query_id", query.ID).Debug("Returning cached result")
			return o.enhanceCachedResult(cached, query), nil
		}
	}

	// 生成执行计划
	plan, err := o.generateExecutionPlan(ctx, query)
	if err != nil {
		o.metrics.IncrementErrorCount()
		return nil, fmt.Errorf("failed to generate execution plan: %w", err)
	}

	// 验证计划可行性
	if err := o.validateExecutionPlan(plan, query.Constraints); err != nil {
		o.metrics.IncrementErrorCount()
		return nil, fmt.Errorf("execution plan validation failed: %w", err)
	}

	// 执行计划
	results, err := o.executePlan(ctx, plan, query)
	if err != nil {
		o.metrics.IncrementErrorCount()
		return nil, fmt.Errorf("plan execution failed: %w", err)
	}

	// 数据关联分析
	correlatedData, err := o.correlator.AnalyzeData(ctx, results, query.Intent)
	if err != nil {
		o.logger.WithError(err).Warn("Data correlation failed")
		correlatedData = &CorrelationResult{Status: "failed"}
	}

	// 生成智能推荐
	recommendations, err := o.generateRecommendations(ctx, query, results, correlatedData)
	if err != nil {
		o.logger.WithError(err).Warn("Failed to generate recommendations")
		recommendations = &IntelligentRecommendations{}
	}

	// 构建结果
	result := &OrchestratedResult{
		QueryID:         query.ID,
		Status:          "completed",
		Intent:          query.Intent,
		ExecutionPlan:   plan,
		Results:         results,
		CorrelatedData:  correlatedData,
		Recommendations: recommendations,
		Metrics: &QueryMetrics{
			TotalExecutionTime: time.Since(startTime),
			PlanGenerationTime: plan.EstimatedTime,
			DataSources:        len(results.Sources),
			ToolCalls:         results.TotalToolCalls,
			SuccessRate:       results.SuccessRate,
		},
		Timestamp: time.Now(),
	}

	// 缓存结果
	if query.Constraints != nil && query.Constraints.CachingEnabled {
		o.cache.Set(query.Query, query.Context, result, time.Hour)
	}

	o.metrics.RecordExecutionTime(time.Since(startTime))
	return result, nil
}

// generateExecutionPlan 生成执行计划
func (o *Orchestrator) generateExecutionPlan(ctx context.Context, query *OrchestratedQuery) (*DetailedExecutionPlan, error) {
	// 获取可用工具
	availableTools, err := o.getAvailableTools()
	if err != nil {
		return nil, fmt.Errorf("failed to get available tools: %w", err)
	}

	// 基于意图和上下文生成初始计划
	initialPlan, err := o.planner.GeneratePlan(query, availableTools)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial plan: %w", err)
	}

	// 使用AI优化执行计划
	if o.aiService != nil {
		optimizedPlan, err := o.optimizePlanWithAI(ctx, initialPlan, query)
		if err != nil {
			o.logger.WithError(err).Warn("AI plan optimization failed, using initial plan")
		} else {
			initialPlan = optimizedPlan
		}
	}

	// 添加依赖关系分析
	o.analyzeDependencies(initialPlan)

	// 估算资源使用和执行时间
	o.estimateResourceUsage(initialPlan)

	// 风险评估
	riskAssessment := o.assessPlanRisk(initialPlan, query.Constraints)
	initialPlan.RiskAssessment = riskAssessment

	return initialPlan, nil
}

// optimizePlanWithAI 使用AI优化执行计划
func (o *Orchestrator) optimizePlanWithAI(ctx context.Context, plan *DetailedExecutionPlan, query *OrchestratedQuery) (*DetailedExecutionPlan, error) {
	// 构建AI优化请求
	optimizationPrompt := fmt.Sprintf(`
作为安全运营专家，请优化以下查询的执行计划：

查询: %s
意图: %s
当前计划包含 %d 个阶段

请分析并提供优化建议：
1. 并行执行机会
2. 工具调用优先级
3. 资源使用优化
4. 风险缓解措施

当前执行计划：
%s
`, query.Query, query.Intent, len(plan.Stages), o.formatPlanForAI(plan))

	aiReq := &ai.QueryRequest{
		Type:    ai.QueryTypeNaturalLanguage,
		Query:   optimizationPrompt,
		Context: query.Context,
	}

	aiResp, err := o.aiService.Query(ctx, aiReq)
	if err != nil {
		return nil, err
	}

	// 解析AI建议并应用到计划中
	return o.applyAIOptimizations(plan, aiResp.Response)
}

// validateExecutionPlan 验证执行计划
func (o *Orchestrator) validateExecutionPlan(plan *DetailedExecutionPlan, constraints *QueryConstraints) error {
	if constraints == nil {
		return nil
	}

	// 检查执行时间限制
	if constraints.MaxExecutionTime > 0 && plan.EstimatedTime > constraints.MaxExecutionTime {
		return fmt.Errorf("estimated execution time %v exceeds limit %v", 
			plan.EstimatedTime, constraints.MaxExecutionTime)
	}

	// 检查并发限制
	maxConcurrency := o.calculateMaxConcurrency(plan)
	if constraints.MaxConcurrency > 0 && maxConcurrency > constraints.MaxConcurrency {
		return fmt.Errorf("plan requires %d concurrent executions, limit is %d", 
			maxConcurrency, constraints.MaxConcurrency)
	}

	// 检查必需数据源
	availableSources := o.getAvailableDataSources(plan)
	for _, required := range constraints.RequiredSources {
		if !contains(availableSources, required) {
			return fmt.Errorf("required data source %s not available", required)
		}
	}

	// 检查排除的数据源
	for _, excluded := range constraints.ExcludedSources {
		if contains(availableSources, excluded) {
			return fmt.Errorf("excluded data source %s is included in plan", excluded)
		}
	}

	return nil
}

// executePlan 执行计划
func (o *Orchestrator) executePlan(ctx context.Context, plan *DetailedExecutionPlan, query *OrchestratedQuery) (*EnhancedResults, error) {
	executor := NewEnhancedExecutor(o.executor, o.logger)
	
	// 设置执行约束
	if query.Constraints != nil {
		executor.SetConstraints(query.Constraints)
	}

	// 按阶段执行
	results := &EnhancedResults{
		Sources:        make(map[string]*SourceResult),
		TotalToolCalls: 0,
		StartTime:      time.Now(),
	}

	for _, stage := range plan.Stages {
		stageResult, err := executor.ExecuteStage(ctx, &stage)
		if err != nil {
			if !stage.CanFailSafe {
				return nil, fmt.Errorf("critical stage %s failed: %w", stage.ID, err)
			}
			o.logger.WithError(err).WithField("stage", stage.ID).Warn("Non-critical stage failed")
		}

		// 合并阶段结果
		o.mergeStageResults(results, stageResult)
	}

	results.EndTime = time.Now()
	results.TotalDuration = results.EndTime.Sub(results.StartTime)
	results.SuccessRate = o.calculateSuccessRate(results)

	return results, nil
}

// 辅助函数

func (o *Orchestrator) getAvailableTools() ([]ai.AvailableTool, error) {
	var tools []ai.AvailableTool
	
	servers := o.mcpManager.ListServers()
	for _, server := range servers {
		serverTools, err := o.mcpManager.ListTools(server.ID)
		if err != nil {
			continue
		}
		
		for _, tool := range serverTools {
			availableTool := ai.AvailableTool{
				Name:        tool.Name,
				Description: tool.Description,
				Server:      server.ID,
			}
			tools = append(tools, availableTool)
		}
	}
	
	return tools, nil
}

func (o *Orchestrator) formatPlanForAI(plan *DetailedExecutionPlan) string {
	// 格式化计划为AI可读的文本
	return fmt.Sprintf("总阶段数: %d, 预估时间: %v", len(plan.Stages), plan.EstimatedTime)
}

func (o *Orchestrator) applyAIOptimizations(plan *DetailedExecutionPlan, aiResponse string) (*DetailedExecutionPlan, error) {
	// 解析AI响应并应用优化建议
	// 这里实现简化版本，实际项目中可以使用更复杂的NLP解析
	optimizedPlan := *plan
	
	// 基于AI建议调整优先级和并行性
	for i := range optimizedPlan.Stages {
		if i > 0 && len(optimizedPlan.Stages[i].Dependencies) == 0 {
			// 无依赖的阶段可以并行执行
			optimizedPlan.Stages[i].Priority = 1
		}
	}
	
	return &optimizedPlan, nil
}

func (o *Orchestrator) analyzeDependencies(plan *DetailedExecutionPlan) {
	dependencies := make(map[string][]string)
	
	for _, stage := range plan.Stages {
		for _, tool := range stage.Tools {
			// 分析工具间的数据依赖
			key := fmt.Sprintf("%s:%s", tool.ServerID, tool.ToolName)
			dependencies[key] = stage.Dependencies
		}
	}
	
	plan.Dependencies = dependencies
}

func (o *Orchestrator) estimateResourceUsage(plan *DetailedExecutionPlan) {
	totalMemory := 0
	totalCPU := 0
	totalNetwork := 0
	
	for _, stage := range plan.Stages {
		// 基于工具类型估算资源使用
		for _, tool := range stage.Tools {
			switch {
			case contains([]string{"search", "query", "list"}, tool.ToolName):
				totalMemory += 100 // MB
				totalCPU += 10     // %
				totalNetwork += 50 // KB/s
			case contains([]string{"scan", "analyze", "correlate"}, tool.ToolName):
				totalMemory += 500 // MB
				totalCPU += 30     // %
				totalNetwork += 100 // KB/s
			default:
				totalMemory += 50  // MB
				totalCPU += 5      // %
				totalNetwork += 25 // KB/s
			}
		}
	}
	
	plan.ResourceUsage = &ResourceEstimation{
		EstimatedMemoryMB:  totalMemory,
		EstimatedCPUPercent: totalCPU,
		EstimatedNetworkKBps: totalNetwork,
	}
}

func (o *Orchestrator) assessPlanRisk(plan *DetailedExecutionPlan, constraints *QueryConstraints) *PlanRiskAssessment {
	riskLevel := "low"
	riskFactors := []string{}
	
	// 评估执行时间风险
	if constraints != nil && constraints.MaxExecutionTime > 0 {
		if plan.EstimatedTime > constraints.MaxExecutionTime*80/100 {
			riskLevel = "medium"
			riskFactors = append(riskFactors, "execution_time_near_limit")
		}
	}
	
	// 评估复杂性风险
	if len(plan.Stages) > 5 {
		if riskLevel == "low" {
			riskLevel = "medium"
		} else {
			riskLevel = "high"
		}
		riskFactors = append(riskFactors, "high_complexity")
	}
	
	return &PlanRiskAssessment{
		RiskLevel:       riskLevel,
		RiskFactors:     riskFactors,
		MitigationSteps: o.generateMitigationSteps(riskFactors),
	}
}

func (o *Orchestrator) calculateMaxConcurrency(plan *DetailedExecutionPlan) int {
	maxConcurrency := 0
	stageGroups := o.groupStagesByDependency(plan.Stages)
	
	for _, group := range stageGroups {
		groupConcurrency := 0
		for _, stage := range group {
			groupConcurrency += len(stage.Tools)
		}
		if groupConcurrency > maxConcurrency {
			maxConcurrency = groupConcurrency
		}
	}
	
	return maxConcurrency
}

func (o *Orchestrator) getAvailableDataSources(plan *DetailedExecutionPlan) []string {
	sources := make(map[string]bool)
	
	for _, stage := range plan.Stages {
		for _, tool := range stage.Tools {
			sources[tool.ServerID] = true
		}
	}
	
	var result []string
	for source := range sources {
		result = append(result, source)
	}
	
	return result
}

func (o *Orchestrator) mergeStageResults(results *EnhancedResults, stageResult *StageResult) {
	if stageResult == nil {
		return
	}
	
	results.TotalToolCalls += stageResult.ToolCallCount
	
	for source, sourceResult := range stageResult.SourceResults {
		if results.Sources[source] == nil {
			results.Sources[source] = &SourceResult{}
		}
		// 合并源结果
		results.Sources[source].Data = append(results.Sources[source].Data, sourceResult.Data...)
	}
}

func (o *Orchestrator) calculateSuccessRate(results *EnhancedResults) float64 {
	if results.TotalToolCalls == 0 {
		return 0.0
	}
	
	successCount := 0
	for _, source := range results.Sources {
		if source.Success {
			successCount++
		}
	}
	
	return float64(successCount) / float64(len(results.Sources))
}

func (o *Orchestrator) groupStagesByDependency(stages []ExecutionStage) [][]ExecutionStage {
	// 简化的依赖分组逻辑
	var groups [][]ExecutionStage
	currentGroup := []ExecutionStage{}
	
	for _, stage := range stages {
		if len(stage.Dependencies) == 0 || len(currentGroup) == 0 {
			currentGroup = append(currentGroup, stage)
		} else {
			groups = append(groups, currentGroup)
			currentGroup = []ExecutionStage{stage}
		}
	}
	
	if len(currentGroup) > 0 {
		groups = append(groups, currentGroup)
	}
	
	return groups
}

func (o *Orchestrator) generateMitigationSteps(riskFactors []string) []string {
	steps := []string{}
	
	for _, factor := range riskFactors {
		switch factor {
		case "execution_time_near_limit":
			steps = append(steps, "考虑增加超时时间或优化查询条件")
		case "high_complexity":
			steps = append(steps, "建议分解为多个简单查询")
		}
	}
	
	return steps
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (o *Orchestrator) enhanceCachedResult(cached *OrchestratedResult, query *OrchestratedQuery) *OrchestratedResult {
	// 增强缓存结果，添加缓存信息
	enhanced := *cached
	enhanced.CacheInfo = &CacheInfo{
		CacheHit:   true,
		CacheAge:   time.Since(cached.Timestamp),
		OriginalID: cached.QueryID,
	}
	enhanced.QueryID = query.ID
	enhanced.Timestamp = time.Now()
	
	return &enhanced
}

func (o *Orchestrator) generateRecommendations(ctx context.Context, query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult) (*IntelligentRecommendations, error) {
	recommendations := &IntelligentRecommendations{
		Immediate: []Recommendation{},
		ShortTerm: []Recommendation{},
		LongTerm:  []Recommendation{},
		Insights:  []AnalysisInsight{},
	}

	// 基于查询意图生成推荐
	switch query.Intent {
	case "threat_analysis":
		recommendations.Immediate = append(recommendations.Immediate, Recommendation{
			Type:        "security_action",
			Title:       "威胁监控加强",
			Description: "建议增强对检测到威胁的持续监控",
			Priority:    "high",
			Impact:      "提升威胁检测能力",
		})
	case "incident_response":
		recommendations.Immediate = append(recommendations.Immediate, Recommendation{
			Type:        "response_action",
			Title:       "应急响应计划",
			Description: "立即启动相关的应急响应流程",
			Priority:    "critical",
			Impact:      "快速遏制安全事件",
		})
	}

	// 基于执行结果生成推荐
	if results.SuccessRate < 0.8 {
		recommendations.ShortTerm = append(recommendations.ShortTerm, Recommendation{
			Type:        "system_improvement",
			Title:       "工具可用性优化",
			Description: "检查和修复失败的MCP服务器连接",
			Priority:    "medium",
			Impact:      "提高查询成功率",
		})
	}

	return recommendations, nil
}