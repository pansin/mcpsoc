package optimization

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// PerformanceOptimizer 性能优化器
type PerformanceOptimizer struct {
	logger           *logrus.Logger
	queryOptimizer   *QueryOptimizer
	cacheManager     *CacheManager
	connectionPool   *ConnectionPool
	circuitBreaker   *CircuitBreaker
	rateLimiter      *RateLimiter
	mu               sync.RWMutex
	enabled          bool
	targetResponseTime time.Duration
}

// NewPerformanceOptimizer 创建性能优化器
func NewPerformanceOptimizer(logger *logrus.Logger) *PerformanceOptimizer {
	return &PerformanceOptimizer{
		logger:             logger,
		queryOptimizer:     NewQueryOptimizer(logger),
		cacheManager:       NewCacheManager(logger),
		connectionPool:     NewConnectionPool(logger),
		circuitBreaker:     NewCircuitBreaker(logger),
		rateLimiter:        NewRateLimiter(logger),
		enabled:            true,
		targetResponseTime: 2 * time.Second, // 目标响应时间2秒
	}
}

// OptimizationContext 优化上下文
type OptimizationContext struct {
	QueryID     string                 `json:"query_id"`
	Query       string                 `json:"query"`
	Intent      string                 `json:"intent"`
	Priority    string                 `json:"priority"`
	Context     map[string]interface{} `json:"context"`
	StartTime   time.Time              `json:"start_time"`
	Deadline    time.Time              `json:"deadline"`
	MaxTools    int                    `json:"max_tools"`
	CacheEnabled bool                  `json:"cache_enabled"`
}

// OptimizationResult 优化结果
type OptimizationResult struct {
	OriginalPlan    *ExecutionPlan    `json:"original_plan"`
	OptimizedPlan   *ExecutionPlan    `json:"optimized_plan"`
	Optimizations   []Optimization    `json:"optimizations"`
	EstimatedTime   time.Duration     `json:"estimated_time"`
	CacheStrategy   *CacheStrategy    `json:"cache_strategy"`
	Recommendations []string          `json:"recommendations"`
}

// ExecutionPlan 执行计划
type ExecutionPlan struct {
	ID              string              `json:"id"`
	Stages          []ExecutionStage    `json:"stages"`
	EstimatedTime   time.Duration       `json:"estimated_time"`
	ToolCount       int                 `json:"tool_count"`
	ParallelStages  int                 `json:"parallel_stages"`
	CriticalPath    []string            `json:"critical_path"`
}

// ExecutionStage 执行阶段
type ExecutionStage struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Tools        []ToolCall    `json:"tools"`
	Dependencies []string      `json:"dependencies"`
	EstimatedTime time.Duration `json:"estimated_time"`
	Priority     int           `json:"priority"`
	CanCache     bool          `json:"can_cache"`
}

// ToolCall 工具调用
type ToolCall struct {
	ServerID      string                 `json:"server_id"`
	ToolName      string                 `json:"tool_name"`
	Arguments     map[string]interface{} `json:"arguments"`
	EstimatedTime time.Duration          `json:"estimated_time"`
	CacheKey      string                 `json:"cache_key"`
	Priority      int                    `json:"priority"`
}

// Optimization 优化项
type Optimization struct {
	Type        string        `json:"type"`
	Description string        `json:"description"`
	TimeSaved   time.Duration `json:"time_saved"`
	Impact      string        `json:"impact"`
}

// OptimizeQuery 优化查询
func (po *PerformanceOptimizer) OptimizeQuery(ctx context.Context, optCtx *OptimizationContext, plan *ExecutionPlan) (*OptimizationResult, error) {
	if !po.enabled {
		return &OptimizationResult{
			OriginalPlan:  plan,
			OptimizedPlan: plan,
		}, nil
	}

	po.logger.WithFields(logrus.Fields{
		"query_id":         optCtx.QueryID,
		"target_time":      po.targetResponseTime,
		"estimated_time":   plan.EstimatedTime,
	}).Info("Starting query optimization")

	startTime := time.Now()
	originalPlan := *plan
	optimizedPlan := *plan
	var optimizations []Optimization

	// 1. 查询优化
	if queryOpts := po.queryOptimizer.OptimizeQuery(&optimizedPlan, optCtx); len(queryOpts) > 0 {
		optimizations = append(optimizations, queryOpts...)
	}

	// 2. 缓存策略优化
	cacheStrategy := po.cacheManager.DetermineCacheStrategy(&optimizedPlan, optCtx)

	// 3. 并行化优化
	if parallelOpts := po.optimizeParallelization(&optimizedPlan); len(parallelOpts) > 0 {
		optimizations = append(optimizations, parallelOpts...)
	}

	// 4. 工具选择优化
	if toolOpts := po.optimizeToolSelection(&optimizedPlan, optCtx); len(toolOpts) > 0 {
		optimizations = append(optimizations, toolOpts...)
	}

	// 5. 超时和降级策略
	po.applyTimeoutStrategy(&optimizedPlan, optCtx)

	// 重新计算估算时间
	optimizedPlan.EstimatedTime = po.calculateEstimatedTime(&optimizedPlan)

	// 生成推荐
	recommendations := po.generateRecommendations(&originalPlan, &optimizedPlan, optCtx)

	result := &OptimizationResult{
		OriginalPlan:    &originalPlan,
		OptimizedPlan:   &optimizedPlan,
		Optimizations:   optimizations,
		EstimatedTime:   optimizedPlan.EstimatedTime,
		CacheStrategy:   cacheStrategy,
		Recommendations: recommendations,
	}

	optimizationTime := time.Since(startTime)
	po.logger.WithFields(logrus.Fields{
		"query_id":         optCtx.QueryID,
		"original_time":    originalPlan.EstimatedTime,
		"optimized_time":   optimizedPlan.EstimatedTime,
		"optimization_time": optimizationTime,
		"optimizations":    len(optimizations),
	}).Info("Query optimization completed")

	return result, nil
}

// QueryOptimizer 查询优化器
type QueryOptimizer struct {
	logger          *logrus.Logger
	toolPerformance map[string]*ToolPerformanceStats
	mu              sync.RWMutex
}

type ToolPerformanceStats struct {
	ToolName        string        `json:"tool_name"`
	ServerID        string        `json:"server_id"`
	AvgResponseTime time.Duration `json:"avg_response_time"`
	SuccessRate     float64       `json:"success_rate"`
	LastUpdated     time.Time     `json:"last_updated"`
	CallCount       int64         `json:"call_count"`
}

func NewQueryOptimizer(logger *logrus.Logger) *QueryOptimizer {
	return &QueryOptimizer{
		logger:          logger,
		toolPerformance: make(map[string]*ToolPerformanceStats),
	}
}

// OptimizeQuery 优化查询计划
func (qo *QueryOptimizer) OptimizeQuery(plan *ExecutionPlan, ctx *OptimizationContext) []Optimization {
	var optimizations []Optimization

	// 1. 工具排序优化
	if opt := qo.optimizeToolOrdering(plan); opt != nil {
		optimizations = append(optimizations, *opt)
	}

	// 2. 冗余工具移除
	if opt := qo.removeRedundantTools(plan); opt != nil {
		optimizations = append(optimizations, *opt)
	}

	// 3. 快速工具优先
	if opt := qo.prioritizeFastTools(plan); opt != nil {
		optimizations = append(optimizations, *opt)
	}

	return optimizations
}

// optimizeToolOrdering 优化工具排序
func (qo *QueryOptimizer) optimizeToolOrdering(plan *ExecutionPlan) *Optimization {
	qo.mu.RLock()
	defer qo.mu.RUnlock()

	optimized := false
	timeSaved := time.Duration(0)

	for _, stage := range plan.Stages {
		if len(stage.Tools) <= 1 {
			continue
		}

		// 根据性能统计重新排序工具
		sort.Slice(stage.Tools, func(i, j int) bool {
			toolI := qo.getToolStats(stage.Tools[i])
			toolJ := qo.getToolStats(stage.Tools[j])
			
			// 优先执行成功率高且响应时间短的工具
			scoreI := toolI.SuccessRate / toolI.AvgResponseTime.Seconds()
			scoreJ := toolJ.SuccessRate / toolJ.AvgResponseTime.Seconds()
			
			return scoreI > scoreJ
		})

		optimized = true
		timeSaved += 200 * time.Millisecond // 估计节省时间
	}

	if optimized {
		return &Optimization{
			Type:        "tool_ordering",
			Description: "重新排序工具调用以提升性能",
			TimeSaved:   timeSaved,
			Impact:      "medium",
		}
	}

	return nil
}

// removeRedundantTools 移除冗余工具
func (qo *QueryOptimizer) removeRedundantTools(plan *ExecutionPlan) *Optimization {
	originalCount := plan.ToolCount
	removedCount := 0

	for _, stage := range plan.Stages {
		toolMap := make(map[string]bool)
		var uniqueTools []ToolCall

		for _, tool := range stage.Tools {
			key := fmt.Sprintf("%s:%s", tool.ServerID, tool.ToolName)
			if !toolMap[key] {
				toolMap[key] = true
				uniqueTools = append(uniqueTools, tool)
			} else {
				removedCount++
			}
		}

		stage.Tools = uniqueTools
	}

	if removedCount > 0 {
		plan.ToolCount = originalCount - removedCount
		return &Optimization{
			Type:        "redundancy_removal",
			Description: fmt.Sprintf("移除了 %d 个冗余工具调用", removedCount),
			TimeSaved:   time.Duration(removedCount) * 100 * time.Millisecond,
			Impact:      "high",
		}
	}

	return nil
}

// prioritizeFastTools 优先执行快速工具
func (qo *QueryOptimizer) prioritizeFastTools(plan *ExecutionPlan) *Optimization {
	qo.mu.RLock()
	defer qo.mu.RUnlock()

	optimized := false
	
	for _, stage := range plan.Stages {
		sort.Slice(stage.Tools, func(i, j int) bool {
			toolI := qo.getToolStats(stage.Tools[i])
			toolJ := qo.getToolStats(stage.Tools[j])
			return toolI.AvgResponseTime < toolJ.AvgResponseTime
		})
		optimized = true
	}

	if optimized {
		return &Optimization{
			Type:        "fast_tools_first",
			Description: "优先执行响应时间短的工具",
			TimeSaved:   300 * time.Millisecond,
			Impact:      "medium",
		}
	}

	return nil
}

// getToolStats 获取工具性能统计
func (qo *QueryOptimizer) getToolStats(tool ToolCall) *ToolPerformanceStats {
	key := fmt.Sprintf("%s:%s", tool.ServerID, tool.ToolName)
	if stats, exists := qo.toolPerformance[key]; exists {
		return stats
	}

	// 返回默认统计
	return &ToolPerformanceStats{
		ToolName:        tool.ToolName,
		ServerID:        tool.ServerID,
		AvgResponseTime: 1 * time.Second,
		SuccessRate:     0.8,
		LastUpdated:     time.Now(),
		CallCount:       0,
	}
}

// 并行化优化
func (po *PerformanceOptimizer) optimizeParallelization(plan *ExecutionPlan) []Optimization {
	var optimizations []Optimization

	// 识别可以并行执行的阶段
	parallelStages := po.identifyParallelStages(plan)
	if parallelStages > plan.ParallelStages {
		plan.ParallelStages = parallelStages
		optimizations = append(optimizations, Optimization{
			Type:        "parallelization",
			Description: fmt.Sprintf("增加并行执行阶段至 %d 个", parallelStages),
			TimeSaved:   500 * time.Millisecond,
			Impact:      "high",
		})
	}

	return optimizations
}

// identifyParallelStages 识别可并行阶段
func (po *PerformanceOptimizer) identifyParallelStages(plan *ExecutionPlan) int {
	dependencyMap := make(map[string][]string)
	for _, stage := range plan.Stages {
		dependencyMap[stage.ID] = stage.Dependencies
	}

	// 简化的并行度计算
	maxParallel := 0
	levels := po.calculateDependencyLevels(dependencyMap)
	
	for _, levelStages := range levels {
		if len(levelStages) > maxParallel {
			maxParallel = len(levelStages)
		}
	}

	return maxParallel
}

// calculateDependencyLevels 计算依赖层级
func (po *PerformanceOptimizer) calculateDependencyLevels(deps map[string][]string) map[int][]string {
	levels := make(map[int][]string)
	processed := make(map[string]bool)
	
	// 简化实现：按依赖数量分层
	for stageID, dependencies := range deps {
		level := len(dependencies)
		levels[level] = append(levels[level], stageID)
		processed[stageID] = true
	}
	
	return levels
}

// 工具选择优化
func (po *PerformanceOptimizer) optimizeToolSelection(plan *ExecutionPlan, ctx *OptimizationContext) []Optimization {
	var optimizations []Optimization

	// 根据优先级过滤工具
	if ctx.Priority == "high" && plan.EstimatedTime > po.targetResponseTime {
		originalCount := plan.ToolCount
		po.filterToolsByPriority(plan, ctx)
		
		if plan.ToolCount < originalCount {
			optimizations = append(optimizations, Optimization{
				Type:        "tool_filtering",
				Description: fmt.Sprintf("根据优先级过滤工具，减少了 %d 个工具调用", originalCount-plan.ToolCount),
				TimeSaved:   time.Duration(originalCount-plan.ToolCount) * 200 * time.Millisecond,
				Impact:      "medium",
			})
		}
	}

	return optimizations
}

// filterToolsByPriority 根据优先级过滤工具
func (po *PerformanceOptimizer) filterToolsByPriority(plan *ExecutionPlan, ctx *OptimizationContext) {
	for _, stage := range plan.Stages {
		var highPriorityTools []ToolCall
		for _, tool := range stage.Tools {
			if tool.Priority >= 2 { // 只保留高优先级工具
				highPriorityTools = append(highPriorityTools, tool)
			}
		}
		stage.Tools = highPriorityTools
	}
	
	// 重新计算工具数量
	totalTools := 0
	for _, stage := range plan.Stages {
		totalTools += len(stage.Tools)
	}
	plan.ToolCount = totalTools
}

// 应用超时策略
func (po *PerformanceOptimizer) applyTimeoutStrategy(plan *ExecutionPlan, ctx *OptimizationContext) {
	// 如果估算时间超过目标时间，应用渐进式超时
	if plan.EstimatedTime > po.targetResponseTime {
		timePerStage := po.targetResponseTime / time.Duration(len(plan.Stages))
		
		for _, stage := range plan.Stages {
			if stage.EstimatedTime > timePerStage {
				stage.EstimatedTime = timePerStage
				
				// 调整工具超时时间
				toolTimeout := timePerStage / time.Duration(len(stage.Tools))
				for i := range stage.Tools {
					stage.Tools[i].EstimatedTime = toolTimeout
				}
			}
		}
	}
}

// calculateEstimatedTime 计算估算时间
func (po *PerformanceOptimizer) calculateEstimatedTime(plan *ExecutionPlan) time.Duration {
	if plan.ParallelStages > 0 {
		// 并行执行：取最长阶段时间
		maxTime := time.Duration(0)
		for _, stage := range plan.Stages {
			if stage.EstimatedTime > maxTime {
				maxTime = stage.EstimatedTime
			}
		}
		return maxTime
	} else {
		// 串行执行：累加所有阶段时间
		totalTime := time.Duration(0)
		for _, stage := range plan.Stages {
			totalTime += stage.EstimatedTime
		}
		return totalTime
	}
}

// generateRecommendations 生成推荐
func (po *PerformanceOptimizer) generateRecommendations(original, optimized *ExecutionPlan, ctx *OptimizationContext) []string {
	var recommendations []string

	// 时间对比建议
	if optimized.EstimatedTime > po.targetResponseTime {
		recommendations = append(recommendations, 
			fmt.Sprintf("查询仍可能超过目标时间(%.1fs)，建议进一步简化查询条件", po.targetResponseTime.Seconds()))
	}

	// 工具数量建议
	if optimized.ToolCount > 10 {
		recommendations = append(recommendations, 
			"工具调用数量较多，建议考虑分批执行或使用更专业的工具")
	}

	// 并行度建议
	if optimized.ParallelStages < 2 {
		recommendations = append(recommendations, 
			"当前查询并行度较低，建议检查工具间依赖关系以提升并行度")
	}

	// 缓存建议
	if ctx.CacheEnabled && len(recommendations) == 0 {
		recommendations = append(recommendations, 
			"查询已经充分优化，建议启用缓存以进一步提升性能")
	}

	return recommendations
}

// CacheManager 缓存管理器
type CacheManager struct {
	logger *logrus.Logger
}

type CacheStrategy struct {
	Enabled    bool          `json:"enabled"`
	TTL        time.Duration `json:"ttl"`
	Scope      string        `json:"scope"`      // query, stage, tool
	Keys       []string      `json:"keys"`
	Priority   int           `json:"priority"`
}

func NewCacheManager(logger *logrus.Logger) *CacheManager {
	return &CacheManager{logger: logger}
}

func (cm *CacheManager) DetermineCacheStrategy(plan *ExecutionPlan, ctx *OptimizationContext) *CacheStrategy {
	if !ctx.CacheEnabled {
		return &CacheStrategy{Enabled: false}
	}

	// 基于查询意图确定缓存策略
	switch ctx.Intent {
	case "threat_analysis":
		return &CacheStrategy{
			Enabled:  true,
			TTL:      5 * time.Minute,
			Scope:    "query",
			Priority: 2,
		}
	case "log_analysis":
		return &CacheStrategy{
			Enabled:  true,
			TTL:      10 * time.Minute,
			Scope:    "stage",
			Priority: 1,
		}
	default:
		return &CacheStrategy{
			Enabled:  true,
			TTL:      15 * time.Minute,
			Scope:    "tool",
			Priority: 1,
		}
	}
}

// ConnectionPool 连接池
type ConnectionPool struct {
	logger *logrus.Logger
}

func NewConnectionPool(logger *logrus.Logger) *ConnectionPool {
	return &ConnectionPool{logger: logger}
}

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	logger *logrus.Logger
}

func NewCircuitBreaker(logger *logrus.Logger) *CircuitBreaker {
	return &CircuitBreaker{logger: logger}
}

// RateLimiter 限流器
type RateLimiter struct {
	logger *logrus.Logger
}

func NewRateLimiter(logger *logrus.Logger) *RateLimiter {
	return &RateLimiter{logger: logger}
}

// UpdateToolPerformance 更新工具性能统计
func (qo *QueryOptimizer) UpdateToolPerformance(serverID, toolName string, responseTime time.Duration, success bool) {
	qo.mu.Lock()
	defer qo.mu.Unlock()

	key := fmt.Sprintf("%s:%s", serverID, toolName)
	stats, exists := qo.toolPerformance[key]
	
	if !exists {
		stats = &ToolPerformanceStats{
			ToolName:        toolName,
			ServerID:        serverID,
			AvgResponseTime: responseTime,
			SuccessRate:     1.0,
			LastUpdated:     time.Now(),
			CallCount:       1,
		}
		if !success {
			stats.SuccessRate = 0.0
		}
	} else {
		// 更新平均响应时间
		stats.AvgResponseTime = (stats.AvgResponseTime*time.Duration(stats.CallCount) + responseTime) / time.Duration(stats.CallCount+1)
		
		// 更新成功率
		totalSuccess := stats.SuccessRate * float64(stats.CallCount)
		if success {
			totalSuccess += 1.0
		}
		stats.CallCount++
		stats.SuccessRate = totalSuccess / float64(stats.CallCount)
		stats.LastUpdated = time.Now()
	}
	
	qo.toolPerformance[key] = stats
}