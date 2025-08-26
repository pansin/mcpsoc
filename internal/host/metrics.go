package host

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// OrchestratorMetrics 编排器指标
type OrchestratorMetrics struct {
	logger *logrus.Logger
	mu     sync.RWMutex

	// 计数器
	totalQueries       uint64
	successfulQueries  uint64
	failedQueries      uint64
	cachedQueries      uint64

	// 执行时间统计
	executionTimes     []time.Duration
	maxExecutionTime   time.Duration
	minExecutionTime   time.Duration
	totalExecutionTime time.Duration

	// 工具调用统计
	totalToolCalls    uint64
	successfulToolCalls uint64
	failedToolCalls   uint64

	// 阶段统计
	stageMetrics map[string]*StageMetrics

	// 数据源统计
	sourceMetrics map[string]*SourceMetrics

	// 时间窗口统计
	hourlyStats map[int]*HourlyStats
	
	// 启动时间
	startTime time.Time
}

// NewOrchestratorMetrics 创建新的编排器指标
func NewOrchestratorMetrics() *OrchestratorMetrics {
	return &OrchestratorMetrics{
		stageMetrics:  make(map[string]*StageMetrics),
		sourceMetrics: make(map[string]*SourceMetrics),
		hourlyStats:   make(map[int]*HourlyStats),
		startTime:     time.Now(),
		minExecutionTime: time.Hour, // 初始化为很大的值
	}
}

// SetLogger 设置日志记录器
func (om *OrchestratorMetrics) SetLogger(logger *logrus.Logger) {
	om.logger = logger
}

// IncrementQueryCount 增加查询计数
func (om *OrchestratorMetrics) IncrementQueryCount() {
	atomic.AddUint64(&om.totalQueries, 1)
	
	// 更新小时统计
	hour := time.Now().Hour()
	om.mu.Lock()
	if om.hourlyStats[hour] == nil {
		om.hourlyStats[hour] = &HourlyStats{}
	}
	om.hourlyStats[hour].QueryCount++
	om.mu.Unlock()
}

// IncrementSuccessCount 增加成功计数
func (om *OrchestratorMetrics) IncrementSuccessCount() {
	atomic.AddUint64(&om.successfulQueries, 1)
}

// IncrementErrorCount 增加错误计数
func (om *OrchestratorMetrics) IncrementErrorCount() {
	atomic.AddUint64(&om.failedQueries, 1)
}

// IncrementCacheHit 增加缓存命中计数
func (om *OrchestratorMetrics) IncrementCacheHit() {
	atomic.AddUint64(&om.cachedQueries, 1)
}

// RecordExecutionTime 记录执行时间
func (om *OrchestratorMetrics) RecordExecutionTime(duration time.Duration) {
	om.mu.Lock()
	defer om.mu.Unlock()

	// 更新执行时间列表（保留最近1000次）
	om.executionTimes = append(om.executionTimes, duration)
	if len(om.executionTimes) > 1000 {
		om.executionTimes = om.executionTimes[len(om.executionTimes)-1000:]
	}

	// 更新统计
	om.totalExecutionTime += duration
	if duration > om.maxExecutionTime {
		om.maxExecutionTime = duration
	}
	if duration < om.minExecutionTime {
		om.minExecutionTime = duration
	}

	// 更新小时统计
	hour := time.Now().Hour()
	if om.hourlyStats[hour] == nil {
		om.hourlyStats[hour] = &HourlyStats{}
	}
	om.hourlyStats[hour].TotalExecutionTime += duration
	if duration > om.hourlyStats[hour].MaxExecutionTime {
		om.hourlyStats[hour].MaxExecutionTime = duration
	}
}

// RecordToolCall 记录工具调用
func (om *OrchestratorMetrics) RecordToolCall(serverID, toolName string, success bool, duration time.Duration) {
	atomic.AddUint64(&om.totalToolCalls, 1)
	
	if success {
		atomic.AddUint64(&om.successfulToolCalls, 1)
	} else {
		atomic.AddUint64(&om.failedToolCalls, 1)
	}

	om.mu.Lock()
	defer om.mu.Unlock()

	// 更新数据源指标
	if om.sourceMetrics[serverID] == nil {
		om.sourceMetrics[serverID] = &SourceMetrics{
			ServerID: serverID,
			ToolStats: make(map[string]*ToolStats),
		}
	}

	sourceMetric := om.sourceMetrics[serverID]
	sourceMetric.TotalCalls++
	sourceMetric.TotalDuration += duration

	if success {
		sourceMetric.SuccessfulCalls++
	} else {
		sourceMetric.FailedCalls++
	}

	// 更新工具统计
	if sourceMetric.ToolStats[toolName] == nil {
		sourceMetric.ToolStats[toolName] = &ToolStats{
			ToolName: toolName,
		}
	}

	toolStat := sourceMetric.ToolStats[toolName]
	toolStat.TotalCalls++
	toolStat.TotalDuration += duration
	
	if success {
		toolStat.SuccessfulCalls++
	} else {
		toolStat.FailedCalls++
	}

	if duration > toolStat.MaxDuration {
		toolStat.MaxDuration = duration
	}
	if toolStat.MinDuration == 0 || duration < toolStat.MinDuration {
		toolStat.MinDuration = duration
	}
}

// RecordStageExecution 记录阶段执行
func (om *OrchestratorMetrics) RecordStageExecution(stageID, stageType string, duration time.Duration, success bool) {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.stageMetrics[stageID] == nil {
		om.stageMetrics[stageID] = &StageMetrics{
			StageID:   stageID,
			StageType: stageType,
		}
	}

	stageMetric := om.stageMetrics[stageID]
	stageMetric.TotalExecutions++
	stageMetric.TotalDuration += duration

	if success {
		stageMetric.SuccessfulExecutions++
	} else {
		stageMetric.FailedExecutions++
	}

	if duration > stageMetric.MaxDuration {
		stageMetric.MaxDuration = duration
	}
	if stageMetric.MinDuration == 0 || duration < stageMetric.MinDuration {
		stageMetric.MinDuration = duration
	}
}

// GetMetrics 获取指标摘要
func (om *OrchestratorMetrics) GetMetrics() *MetricsSummary {
	om.mu.RLock()
	defer om.mu.RUnlock()

	summary := &MetricsSummary{
		TotalQueries:       atomic.LoadUint64(&om.totalQueries),
		SuccessfulQueries:  atomic.LoadUint64(&om.successfulQueries),
		FailedQueries:      atomic.LoadUint64(&om.failedQueries),
		CachedQueries:      atomic.LoadUint64(&om.cachedQueries),
		TotalToolCalls:     atomic.LoadUint64(&om.totalToolCalls),
		SuccessfulToolCalls: atomic.LoadUint64(&om.successfulToolCalls),
		FailedToolCalls:    atomic.LoadUint64(&om.failedToolCalls),
		MaxExecutionTime:   om.maxExecutionTime,
		MinExecutionTime:   om.minExecutionTime,
		UpTime:            time.Since(om.startTime),
		StageMetrics:      make(map[string]*StageMetrics),
		SourceMetrics:     make(map[string]*SourceMetrics),
		HourlyStats:       make(map[int]*HourlyStats),
	}

	// 计算平均执行时间
	if len(om.executionTimes) > 0 {
		total := time.Duration(0)
		for _, duration := range om.executionTimes {
			total += duration
		}
		summary.AvgExecutionTime = total / time.Duration(len(om.executionTimes))
	}

	// 计算成功率
	totalQueries := summary.TotalQueries
	if totalQueries > 0 {
		summary.SuccessRate = float64(summary.SuccessfulQueries) / float64(totalQueries)
	}

	// 计算工具调用成功率
	totalToolCalls := summary.TotalToolCalls
	if totalToolCalls > 0 {
		summary.ToolSuccessRate = float64(summary.SuccessfulToolCalls) / float64(totalToolCalls)
	}

	// 计算缓存命中率
	if totalQueries > 0 {
		summary.CacheHitRate = float64(summary.CachedQueries) / float64(totalQueries)
	}

	// 复制阶段指标
	for k, v := range om.stageMetrics {
		stageMetricCopy := *v
		if stageMetricCopy.TotalExecutions > 0 {
			stageMetricCopy.AvgDuration = stageMetricCopy.TotalDuration / time.Duration(stageMetricCopy.TotalExecutions)
			stageMetricCopy.SuccessRate = float64(stageMetricCopy.SuccessfulExecutions) / float64(stageMetricCopy.TotalExecutions)
		}
		summary.StageMetrics[k] = &stageMetricCopy
	}

	// 复制数据源指标
	for k, v := range om.sourceMetrics {
		sourceMetricCopy := *v
		if sourceMetricCopy.TotalCalls > 0 {
			sourceMetricCopy.AvgDuration = sourceMetricCopy.TotalDuration / time.Duration(sourceMetricCopy.TotalCalls)
			sourceMetricCopy.SuccessRate = float64(sourceMetricCopy.SuccessfulCalls) / float64(sourceMetricCopy.TotalCalls)
		}
		
		// 复制工具统计
		sourceMetricCopy.ToolStats = make(map[string]*ToolStats)
		for toolName, toolStat := range v.ToolStats {
			toolStatCopy := *toolStat
			if toolStatCopy.TotalCalls > 0 {
				toolStatCopy.AvgDuration = toolStatCopy.TotalDuration / time.Duration(toolStatCopy.TotalCalls)
				toolStatCopy.SuccessRate = float64(toolStatCopy.SuccessfulCalls) / float64(toolStatCopy.TotalCalls)
			}
			sourceMetricCopy.ToolStats[toolName] = &toolStatCopy
		}
		
		summary.SourceMetrics[k] = &sourceMetricCopy
	}

	// 复制小时统计
	for k, v := range om.hourlyStats {
		hourlyStatCopy := *v
		if hourlyStatCopy.QueryCount > 0 {
			hourlyStatCopy.AvgExecutionTime = hourlyStatCopy.TotalExecutionTime / time.Duration(hourlyStatCopy.QueryCount)
		}
		summary.HourlyStats[k] = &hourlyStatCopy
	}

	return summary
}

// GetPerformanceReport 获取性能报告
func (om *OrchestratorMetrics) GetPerformanceReport() *PerformanceReport {
	metrics := om.GetMetrics()
	
	report := &PerformanceReport{
		GeneratedAt: time.Now(),
		UpTime:     metrics.UpTime,
		Summary:    metrics,
	}

	// 性能分析
	report.Analysis = &PerformanceAnalysis{}

	// 查询性能分析
	if metrics.AvgExecutionTime > 5*time.Second {
		report.Analysis.Recommendations = append(report.Analysis.Recommendations, 
			"查询平均执行时间较长，建议优化查询逻辑或增加缓存")
	}

	// 成功率分析
	if metrics.SuccessRate < 0.9 {
		report.Analysis.Recommendations = append(report.Analysis.Recommendations,
			"查询成功率偏低，建议检查MCP服务器连接和工具可用性")
	}

	// 缓存效率分析
	if metrics.CacheHitRate < 0.1 {
		report.Analysis.Recommendations = append(report.Analysis.Recommendations,
			"缓存命中率较低，建议优化缓存策略")
	}

	// 工具调用分析
	if metrics.ToolSuccessRate < 0.8 {
		report.Analysis.Recommendations = append(report.Analysis.Recommendations,
			"工具调用成功率偏低，建议检查MCP服务器状态")
	}

	// 识别最慢的数据源
	var slowestSource string
	var slowestAvgTime time.Duration
	for _, sourceMetric := range metrics.SourceMetrics {
		if sourceMetric.AvgDuration > slowestAvgTime {
			slowestAvgTime = sourceMetric.AvgDuration
			slowestSource = sourceMetric.ServerID
		}
	}
	if slowestSource != "" {
		report.Analysis.SlowestDataSource = slowestSource
		report.Analysis.SlowestAvgTime = slowestAvgTime
	}

	// 识别最活跃的小时
	var busiestHour int
	var maxQueryCount uint64
	for hour, stats := range metrics.HourlyStats {
		if stats.QueryCount > maxQueryCount {
			maxQueryCount = stats.QueryCount
			busiestHour = hour
		}
	}
	report.Analysis.BusiestHour = busiestHour
	report.Analysis.BusiestHourQueries = maxQueryCount

	return report
}

// Reset 重置指标
func (om *OrchestratorMetrics) Reset() {
	om.mu.Lock()
	defer om.mu.Unlock()

	atomic.StoreUint64(&om.totalQueries, 0)
	atomic.StoreUint64(&om.successfulQueries, 0)
	atomic.StoreUint64(&om.failedQueries, 0)
	atomic.StoreUint64(&om.cachedQueries, 0)
	atomic.StoreUint64(&om.totalToolCalls, 0)
	atomic.StoreUint64(&om.successfulToolCalls, 0)
	atomic.StoreUint64(&om.failedToolCalls, 0)

	om.executionTimes = []time.Duration{}
	om.maxExecutionTime = 0
	om.minExecutionTime = time.Hour
	om.totalExecutionTime = 0

	om.stageMetrics = make(map[string]*StageMetrics)
	om.sourceMetrics = make(map[string]*SourceMetrics)
	om.hourlyStats = make(map[int]*HourlyStats)
	om.startTime = time.Now()

	if om.logger != nil {
		om.logger.Info("Orchestrator metrics reset")
	}
}

// 数据结构定义

// MetricsSummary 指标摘要
type MetricsSummary struct {
	TotalQueries        uint64                    `json:"total_queries"`
	SuccessfulQueries   uint64                    `json:"successful_queries"`
	FailedQueries       uint64                    `json:"failed_queries"`
	CachedQueries       uint64                    `json:"cached_queries"`
	TotalToolCalls      uint64                    `json:"total_tool_calls"`
	SuccessfulToolCalls uint64                    `json:"successful_tool_calls"`
	FailedToolCalls     uint64                    `json:"failed_tool_calls"`
	AvgExecutionTime    time.Duration             `json:"avg_execution_time"`
	MaxExecutionTime    time.Duration             `json:"max_execution_time"`
	MinExecutionTime    time.Duration             `json:"min_execution_time"`
	SuccessRate         float64                   `json:"success_rate"`
	ToolSuccessRate     float64                   `json:"tool_success_rate"`
	CacheHitRate        float64                   `json:"cache_hit_rate"`
	UpTime              time.Duration             `json:"up_time"`
	StageMetrics        map[string]*StageMetrics  `json:"stage_metrics"`
	SourceMetrics       map[string]*SourceMetrics `json:"source_metrics"`
	HourlyStats         map[int]*HourlyStats      `json:"hourly_stats"`
}

// StageMetrics 阶段指标
type StageMetrics struct {
	StageID              string        `json:"stage_id"`
	StageType            string        `json:"stage_type"`
	TotalExecutions      uint64        `json:"total_executions"`
	SuccessfulExecutions uint64        `json:"successful_executions"`
	FailedExecutions     uint64        `json:"failed_executions"`
	TotalDuration        time.Duration `json:"total_duration"`
	AvgDuration          time.Duration `json:"avg_duration"`
	MaxDuration          time.Duration `json:"max_duration"`
	MinDuration          time.Duration `json:"min_duration"`
	SuccessRate          float64       `json:"success_rate"`
}

// SourceMetrics 数据源指标
type SourceMetrics struct {
	ServerID        string                 `json:"server_id"`
	TotalCalls      uint64                 `json:"total_calls"`
	SuccessfulCalls uint64                 `json:"successful_calls"`
	FailedCalls     uint64                 `json:"failed_calls"`
	TotalDuration   time.Duration          `json:"total_duration"`
	AvgDuration     time.Duration          `json:"avg_duration"`
	SuccessRate     float64                `json:"success_rate"`
	ToolStats       map[string]*ToolStats  `json:"tool_stats"`
}

// ToolStats 工具统计
type ToolStats struct {
	ToolName        string        `json:"tool_name"`
	TotalCalls      uint64        `json:"total_calls"`
	SuccessfulCalls uint64        `json:"successful_calls"`
	FailedCalls     uint64        `json:"failed_calls"`
	TotalDuration   time.Duration `json:"total_duration"`
	AvgDuration     time.Duration `json:"avg_duration"`
	MaxDuration     time.Duration `json:"max_duration"`
	MinDuration     time.Duration `json:"min_duration"`
	SuccessRate     float64       `json:"success_rate"`
}

// HourlyStats 小时统计
type HourlyStats struct {
	QueryCount         uint64        `json:"query_count"`
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	AvgExecutionTime   time.Duration `json:"avg_execution_time"`
	MaxExecutionTime   time.Duration `json:"max_execution_time"`
}

// PerformanceReport 性能报告
type PerformanceReport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	UpTime      time.Duration       `json:"up_time"`
	Summary     *MetricsSummary     `json:"summary"`
	Analysis    *PerformanceAnalysis `json:"analysis"`
}

// PerformanceAnalysis 性能分析
type PerformanceAnalysis struct {
	Recommendations    []string      `json:"recommendations"`
	SlowestDataSource  string        `json:"slowest_data_source"`
	SlowestAvgTime     time.Duration `json:"slowest_avg_time"`
	BusiestHour        int           `json:"busiest_hour"`
	BusiestHourQueries uint64        `json:"busiest_hour_queries"`
}

// QueryMetrics 查询指标
type QueryMetrics struct {
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	PlanGenerationTime time.Duration `json:"plan_generation_time"`
	DataSources        int           `json:"data_sources"`
	ToolCalls          int           `json:"tool_calls"`
	SuccessRate        float64       `json:"success_rate"`
}