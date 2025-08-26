package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// MonitoringSystem 监控系统
type MonitoringSystem struct {
	logger       *logrus.Logger
	registry     *prometheus.Registry
	server       *http.Server
	metrics      *SystemMetrics
	healthChecks map[string]HealthChecker
	mu           sync.RWMutex
	enabled      bool
}

// NewMonitoringSystem 创建监控系统
func NewMonitoringSystem(logger *logrus.Logger, port int) *MonitoringSystem {
	registry := prometheus.NewRegistry()
	metrics := NewSystemMetrics()
	
	// 注册系统指标
	registry.MustRegister(metrics.GetCollectors()...)
	
	// 创建HTTP服务器
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/ready", handleReady)
	
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	
	return &MonitoringSystem{
		logger:       logger,
		registry:     registry,
		server:       server,
		metrics:      metrics,
		healthChecks: make(map[string]HealthChecker),
		enabled:      true,
	}
}

// SystemMetrics 系统指标
type SystemMetrics struct {
	// 查询指标
	QueryTotal       prometheus.Counter
	QueryDuration    prometheus.Histogram
	QueryErrors      prometheus.Counter
	QuerySuccess     prometheus.Counter
	
	// MCP连接指标
	MCPConnections   prometheus.Gauge
	MCPToolCalls     prometheus.Counter
	MCPCallDuration  prometheus.Histogram
	MCPCallErrors    prometheus.Counter
	
	// AI服务指标
	AIRequests       prometheus.Counter
	AITokens         prometheus.Counter
	AILatency        prometheus.Histogram
	AIErrors         prometheus.Counter
	
	// 威胁检测指标
	ThreatDetections prometheus.Counter
	ThreatAlerts     prometheus.Counter
	ThreatsByLevel   *prometheus.CounterVec
	
	// 系统资源指标
	CPUUsage         prometheus.Gauge
	MemoryUsage      prometheus.Gauge
	GoroutineCount   prometheus.Gauge
	
	// 缓存指标
	CacheHits        prometheus.Counter
	CacheMisses      prometheus.Counter
	CacheSize        prometheus.Gauge
}

// NewSystemMetrics 创建系统指标
func NewSystemMetrics() *SystemMetrics {
	return &SystemMetrics{
		// 查询指标
		QueryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_queries_total",
			Help: "Total number of queries processed",
		}),
		QueryDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "mcpsoc_query_duration_seconds",
			Help:    "Duration of query processing in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		QueryErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_query_errors_total",
			Help: "Total number of query errors",
		}),
		QuerySuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_query_success_total",
			Help: "Total number of successful queries",
		}),
		
		// MCP连接指标
		MCPConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpsoc_mcp_connections",
			Help: "Number of active MCP connections",
		}),
		MCPToolCalls: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_mcp_tool_calls_total",
			Help: "Total number of MCP tool calls",
		}),
		MCPCallDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "mcpsoc_mcp_call_duration_seconds",
			Help:    "Duration of MCP tool calls in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		MCPCallErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_mcp_call_errors_total",
			Help: "Total number of MCP tool call errors",
		}),
		
		// AI服务指标
		AIRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_ai_requests_total",
			Help: "Total number of AI service requests",
		}),
		AITokens: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_ai_tokens_total",
			Help: "Total number of AI tokens consumed",
		}),
		AILatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "mcpsoc_ai_latency_seconds",
			Help:    "AI service response latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		AIErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_ai_errors_total",
			Help: "Total number of AI service errors",
		}),
		
		// 威胁检测指标
		ThreatDetections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_threat_detections_total",
			Help: "Total number of threat detections",
		}),
		ThreatAlerts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_threat_alerts_total",
			Help: "Total number of threat alerts generated",
		}),
		ThreatsByLevel: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mcpsoc_threats_by_level_total",
				Help: "Total number of threats by severity level",
			},
			[]string{"level"},
		),
		
		// 系统资源指标
		CPUUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpsoc_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),
		MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpsoc_memory_usage_bytes",
			Help: "Current memory usage in bytes",
		}),
		GoroutineCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpsoc_goroutines",
			Help: "Number of goroutines",
		}),
		
		// 缓存指标
		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_cache_hits_total",
			Help: "Total number of cache hits",
		}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpsoc_cache_misses_total",
			Help: "Total number of cache misses",
		}),
		CacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpsoc_cache_size",
			Help: "Current cache size",
		}),
	}
}

// GetCollectors 获取所有收集器
func (sm *SystemMetrics) GetCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		sm.QueryTotal,
		sm.QueryDuration,
		sm.QueryErrors,
		sm.QuerySuccess,
		sm.MCPConnections,
		sm.MCPToolCalls,
		sm.MCPCallDuration,
		sm.MCPCallErrors,
		sm.AIRequests,
		sm.AITokens,
		sm.AILatency,
		sm.AIErrors,
		sm.ThreatDetections,
		sm.ThreatAlerts,
		sm.ThreatsByLevel,
		sm.CPUUsage,
		sm.MemoryUsage,
		sm.GoroutineCount,
		sm.CacheHits,
		sm.CacheMisses,
		sm.CacheSize,
	}
}

// HealthChecker 健康检查接口
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) error
}

// HealthStatus 健康状态
type HealthStatus struct {
	Status  string            `json:"status"`
	Checks  map[string]string `json:"checks"`
	Message string            `json:"message,omitempty"`
}

// Start 启动监控系统
func (ms *MonitoringSystem) Start() error {
	ms.logger.WithField("addr", ms.server.Addr).Info("Starting monitoring server")
	
	// 启动系统资源监控
	go ms.startResourceMonitoring()
	
	// 启动HTTP服务器
	go func() {
		if err := ms.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ms.logger.WithError(err).Error("Monitoring server failed")
		}
	}()
	
	return nil
}

// Stop 停止监控系统
func (ms *MonitoringSystem) Stop(ctx context.Context) error {
	ms.logger.Info("Stopping monitoring server")
	return ms.server.Shutdown(ctx)
}

// RegisterHealthCheck 注册健康检查
func (ms *MonitoringSystem) RegisterHealthCheck(name string, checker HealthChecker) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	ms.healthChecks[name] = checker
	ms.logger.WithField("check_name", name).Info("Health check registered")
}

// GetHealthStatus 获取健康状态
func (ms *MonitoringSystem) GetHealthStatus(ctx context.Context) *HealthStatus {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	
	status := &HealthStatus{
		Status: "healthy",
		Checks: make(map[string]string),
	}
	
	allHealthy := true
	for name, checker := range ms.healthChecks {
		if err := checker.Check(ctx); err != nil {
			status.Checks[name] = fmt.Sprintf("unhealthy: %v", err)
			allHealthy = false
		} else {
			status.Checks[name] = "healthy"
		}
	}
	
	if !allHealthy {
		status.Status = "unhealthy"
		status.Message = "One or more health checks failed"
	}
	
	return status
}

// 指标记录方法
func (ms *MonitoringSystem) RecordQuery(duration time.Duration, success bool) {
	ms.metrics.QueryTotal.Inc()
	ms.metrics.QueryDuration.Observe(duration.Seconds())
	if success {
		ms.metrics.QuerySuccess.Inc()
	} else {
		ms.metrics.QueryErrors.Inc()
	}
}

func (ms *MonitoringSystem) RecordMCPCall(duration time.Duration, success bool) {
	ms.metrics.MCPToolCalls.Inc()
	ms.metrics.MCPCallDuration.Observe(duration.Seconds())
	if !success {
		ms.metrics.MCPCallErrors.Inc()
	}
}

func (ms *MonitoringSystem) RecordAIRequest(tokens int, duration time.Duration, success bool) {
	ms.metrics.AIRequests.Inc()
	ms.metrics.AITokens.Add(float64(tokens))
	ms.metrics.AILatency.Observe(duration.Seconds())
	if !success {
		ms.metrics.AIErrors.Inc()
	}
}

func (ms *MonitoringSystem) RecordThreatDetection(level string) {
	ms.metrics.ThreatDetections.Inc()
	ms.metrics.ThreatsByLevel.WithLabelValues(level).Inc()
}

func (ms *MonitoringSystem) RecordThreatAlert() {
	ms.metrics.ThreatAlerts.Inc()
}

func (ms *MonitoringSystem) SetMCPConnections(count int) {
	ms.metrics.MCPConnections.Set(float64(count))
}

func (ms *MonitoringSystem) RecordCacheHit() {
	ms.metrics.CacheHits.Inc()
}

func (ms *MonitoringSystem) RecordCacheMiss() {
	ms.metrics.CacheMisses.Inc()
}

func (ms *MonitoringSystem) SetCacheSize(size int) {
	ms.metrics.CacheSize.Set(float64(size))
}

// startResourceMonitoring 启动系统资源监控
func (ms *MonitoringSystem) startResourceMonitoring() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		// 更新内存使用
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		ms.metrics.MemoryUsage.Set(float64(m.Alloc))
		
		// 更新协程数量
		ms.metrics.GoroutineCount.Set(float64(runtime.NumGoroutine()))
		
		// CPU使用率需要额外的计算，这里简化处理
		// 实际项目中可以使用第三方库获取更准确的CPU使用率
	}
}

// HTTP处理器
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// 内置健康检查实现

// DatabaseHealthChecker 数据库健康检查
type DatabaseHealthChecker struct {
	name string
	ping func() error
}

func NewDatabaseHealthChecker(name string, pingFunc func() error) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{
		name: name,
		ping: pingFunc,
	}
}

func (dhc *DatabaseHealthChecker) Name() string {
	return dhc.name
}

func (dhc *DatabaseHealthChecker) Check(ctx context.Context) error {
	return dhc.ping()
}

// MCPServerHealthChecker MCP服务器健康检查
type MCPServerHealthChecker struct {
	name     string
	serverID string
	manager  MCPManager
}

type MCPManager interface {
	IsServerHealthy(serverID string) bool
}

func NewMCPServerHealthChecker(name, serverID string, manager MCPManager) *MCPServerHealthChecker {
	return &MCPServerHealthChecker{
		name:     name,
		serverID: serverID,
		manager:  manager,
	}
}

func (mhc *MCPServerHealthChecker) Name() string {
	return mhc.name
}

func (mhc *MCPServerHealthChecker) Check(ctx context.Context) error {
	if !mhc.manager.IsServerHealthy(mhc.serverID) {
		return fmt.Errorf("MCP server %s is unhealthy", mhc.serverID)
	}
	return nil
}

// AIServiceHealthChecker AI服务健康检查
type AIServiceHealthChecker struct {
	name    string
	service AIService
}

type AIService interface {
	IsAvailable(ctx context.Context) bool
}

func NewAIServiceHealthChecker(name string, service AIService) *AIServiceHealthChecker {
	return &AIServiceHealthChecker{
		name:    name,
		service: service,
	}
}

func (ahc *AIServiceHealthChecker) Name() string {
	return ahc.name
}

func (ahc *AIServiceHealthChecker) Check(ctx context.Context) error {
	if !ahc.service.IsAvailable(ctx) {
		return fmt.Errorf("AI service %s is unavailable", ahc.name)
	}
	return nil
}