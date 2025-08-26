package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// ModSecurityServer ModSecurity WAF MCP服务器
type ModSecurityServer struct {
	capabilities    *mcp.ServerCapabilities
	tools          []mcp.Tool
	resources      []mcp.Resource
	attackLogs     []AttackLog
	blockedIPs     []BlockedIP
	wafRules       []WAFRule
	httpLogs       []HTTPLog
	wafConfig      *WAFConfig
}

// AttackLog 攻击日志
type AttackLog struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	SourceIP     string    `json:"source_ip"`
	TargetURL    string    `json:"target_url"`
	AttackType   string    `json:"attack_type"`
	Severity     string    `json:"severity"`       // low, medium, high, critical
	RuleID       string    `json:"rule_id"`
	RuleMessage  string    `json:"rule_message"`
	Action       string    `json:"action"`         // block, warn, log
	UserAgent    string    `json:"user_agent"`
	RequestMethod string   `json:"request_method"`
	RequestBody  string    `json:"request_body"`
	ResponseCode int       `json:"response_code"`
	Blocked      bool      `json:"blocked"`
	Country      string    `json:"country"`
	ASN          string    `json:"asn"`
}

// BlockedIP 被阻止的IP
type BlockedIP struct {
	IP           string    `json:"ip"`
	Reason       string    `json:"reason"`
	BlockedAt    time.Time `json:"blocked_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	AttackCount  int       `json:"attack_count"`
	LastAttack   time.Time `json:"last_attack"`
	Country      string    `json:"country"`
	ASN          string    `json:"asn"`
	Status       string    `json:"status"`       // active, expired, manual
}

// WAFRule WAF规则
type WAFRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	RuleBody    string    `json:"rule_body"`
	Category    string    `json:"category"`     // owasp, custom, third_party
	Severity    string    `json:"severity"`
	Action      string    `json:"action"`       // block, deny, warn, log
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Tags        []string  `json:"tags"`
	HitCount    int       `json:"hit_count"`
}

// HTTPLog HTTP请求日志
type HTTPLog struct {
	ID            string            `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	SourceIP      string            `json:"source_ip"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	UserAgent     string            `json:"user_agent"`
	ResponseCode  int               `json:"response_code"`
	ResponseSize  int64             `json:"response_size"`
	ResponseTime  int64             `json:"response_time"` // 毫秒
	Headers       map[string]string `json:"headers"`
	QueryParams   map[string]string `json:"query_params"`
	RequestBody   string            `json:"request_body"`
	ThreatScore   float64           `json:"threat_score"`
	RulesTriggered []string         `json:"rules_triggered"`
}

// WAFConfig WAF配置
type WAFConfig struct {
	Mode               string    `json:"mode"`                 // learning, blocking, monitoring
	CoreRuleSetVersion string    `json:"core_rule_set_version"`
	ParanoiaLevel      int       `json:"paranoia_level"`
	RequestBodyLimit   int64     `json:"request_body_limit"`
	ResponseBodyLimit  int64     `json:"response_body_limit"`
	IPWhitelist        []string  `json:"ip_whitelist"`
	IPBlacklist        []string  `json:"ip_blacklist"`
	EnableGeoBlocking  bool      `json:"enable_geo_blocking"`
	BlockedCountries   []string  `json:"blocked_countries"`
	RateLimiting      *RateLimit `json:"rate_limiting"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// RateLimit 速率限制配置
type RateLimit struct {
	Enabled         bool  `json:"enabled"`
	RequestsPerMinute int `json:"requests_per_minute"`
	BurstSize       int   `json:"burst_size"`
	WindowSize      int   `json:"window_size"` // 秒
}

// NewModSecurityServer 创建ModSecurity服务器
func NewModSecurityServer() *ModSecurityServer {
	server := &ModSecurityServer{
		capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolsCapability{
				ListChanged: false,
			},
			Resources: &mcp.ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
		},
		attackLogs: []AttackLog{},
		blockedIPs: []BlockedIP{},
		wafRules:   []WAFRule{},
		httpLogs:   []HTTPLog{},
		wafConfig: &WAFConfig{
			Mode:               "blocking",
			CoreRuleSetVersion: "3.3.2",
			ParanoiaLevel:      2,
			RequestBodyLimit:   13107200, // 12.5MB
			ResponseBodyLimit:  524288,   // 512KB
			IPWhitelist:        []string{"127.0.0.1", "::1"},
			IPBlacklist:        []string{},
			EnableGeoBlocking:  false,
			BlockedCountries:   []string{},
			RateLimiting: &RateLimit{
				Enabled:           true,
				RequestsPerMinute: 300,
				BurstSize:         50,
				WindowSize:        60,
			},
			UpdatedAt: time.Now(),
		},
	}

	server.initializeTools()
	server.initializeResources()
	server.loadDefaultRules()
	server.loadSampleData()

	return server
}

// initializeTools 初始化工具
func (s *ModSecurityServer) initializeTools() {
	s.tools = []mcp.Tool{
		{
			Name:        "analyze_request",
			Description: "分析HTTP请求是否包含攻击",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"request_data": {
						Type:        "object",
						Description: "HTTP请求数据",
						Properties: map[string]mcp.JSONSchema{
							"method": {
								Type:        "string",
								Description: "请求方法",
							},
							"url": {
								Type:        "string",
								Description: "请求URL",
							},
							"headers": {
								Type:        "object",
								Description: "请求头",
							},
							"body": {
								Type:        "string",
								Description: "请求体",
							},
							"source_ip": {
								Type:        "string",
								Description: "源IP地址",
							},
						},
					},
					"paranoia_level": {
						Type:        "integer",
						Description: "偏执级别 (1-4)",
					},
				},
				Required: []string{"request_data"},
			},
		},
		{
			Name:        "block_ip",
			Description: "阻止指定IP地址",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ip_address": {
						Type:        "string",
						Description: "要阻止的IP地址",
					},
					"reason": {
						Type:        "string",
						Description: "阻止原因",
					},
					"duration": {
						Type:        "integer",
						Description: "阻止时长(分钟)，0表示永久",
					},
				},
				Required: []string{"ip_address", "reason"},
			},
		},
		{
			Name:        "unblock_ip",
			Description: "解除IP地址阻止",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ip_address": {
						Type:        "string",
						Description: "要解除阻止的IP地址",
					},
				},
				Required: []string{"ip_address"},
			},
		},
		{
			Name:        "get_attack_logs",
			Description: "获取攻击日志",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"start_time": {
						Type:        "string",
						Description: "开始时间 (RFC3339格式)",
					},
					"end_time": {
						Type:        "string",
						Description: "结束时间 (RFC3339格式)",
					},
					"attack_type": {
						Type:        "string",
						Description: "攻击类型过滤",
					},
					"severity": {
						Type:        "string",
						Description: "严重程度过滤",
						Enum:        []interface{}{"low", "medium", "high", "critical"},
					},
					"source_ip": {
						Type:        "string",
						Description: "源IP过滤",
					},
					"limit": {
						Type:        "integer",
						Description: "结果数量限制",
					},
				},
			},
		},
		{
			Name:        "update_waf_config",
			Description: "更新WAF配置",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"mode": {
						Type:        "string",
						Description: "WAF模式",
						Enum:        []interface{}{"learning", "blocking", "monitoring"},
					},
					"paranoia_level": {
						Type:        "integer",
						Description: "偏执级别 (1-4)",
					},
					"ip_whitelist": {
						Type:        "array",
						Description: "IP白名单",
						Items:       &mcp.JSONSchema{Type: "string"},
					},
					"ip_blacklist": {
						Type:        "array",
						Description: "IP黑名单",
						Items:       &mcp.JSONSchema{Type: "string"},
					},
					"rate_limiting": {
						Type:        "object",
						Description: "速率限制配置",
						Properties: map[string]mcp.JSONSchema{
							"enabled": {
								Type:        "boolean",
								Description: "启用速率限制",
							},
							"requests_per_minute": {
								Type:        "integer",
								Description: "每分钟请求数",
							},
						},
					},
				},
			},
		},
		{
			Name:        "create_custom_rule",
			Description: "创建自定义WAF规则",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"name": {
						Type:        "string",
						Description: "规则名称",
					},
					"description": {
						Type:        "string",
						Description: "规则描述",
					},
					"rule_body": {
						Type:        "string",
						Description: "ModSecurity规则体",
					},
					"severity": {
						Type:        "string",
						Description: "严重程度",
						Enum:        []interface{}{"low", "medium", "high", "critical"},
					},
					"action": {
						Type:        "string",
						Description: "触发动作",
						Enum:        []interface{}{"block", "deny", "warn", "log"},
					},
					"tags": {
						Type:        "array",
						Description: "规则标签",
						Items:       &mcp.JSONSchema{Type: "string"},
					},
				},
				Required: []string{"name", "rule_body", "severity", "action"},
			},
		},
		{
			Name:        "test_rule",
			Description: "测试WAF规则",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"rule_id": {
						Type:        "string",
						Description: "规则ID",
					},
					"test_requests": {
						Type:        "array",
						Description: "测试请求",
						Items: &mcp.JSONSchema{
							Type: "object",
							Properties: map[string]mcp.JSONSchema{
								"method": {Type: "string"},
								"url":    {Type: "string"},
								"body":   {Type: "string"},
							},
						},
					},
				},
				Required: []string{"rule_id", "test_requests"},
			},
		},
		{
			Name:        "generate_report",
			Description: "生成安全报告",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"report_type": {
						Type:        "string",
						Description: "报告类型",
						Enum:        []interface{}{"daily", "weekly", "monthly", "attack_summary", "top_threats"},
					},
					"start_date": {
						Type:        "string",
						Description: "开始日期 (YYYY-MM-DD)",
					},
					"end_date": {
						Type:        "string",
						Description: "结束日期 (YYYY-MM-DD)",
					},
					"format": {
						Type:        "string",
						Description: "报告格式",
						Enum:        []interface{}{"json", "html", "pdf", "csv"},
					},
				},
				Required: []string{"report_type"},
			},
		},
	}
}

// loadDefaultRules 加载默认WAF规则
func (s *ModSecurityServer) loadDefaultRules() {
	defaultRules := []WAFRule{
		{
			ID:          "rule-001",
			Name:        "SQL注入检测",
			Description: "检测常见的SQL注入攻击模式",
			RuleBody:    "SecRule ARGS \"@detectSQLi\" \"id:001,phase:2,block,msg:'SQL Injection Attack Detected'\"",
			Category:    "owasp",
			Severity:    "high",
			Action:      "block",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Tags:        []string{"sqli", "injection", "owasp-top10"},
			HitCount:    0,
		},
		{
			ID:          "rule-002",
			Name:        "XSS攻击检测",
			Description: "检测跨站脚本攻击",
			RuleBody:    "SecRule ARGS \"@detectXSS\" \"id:002,phase:2,block,msg:'XSS Attack Detected'\"",
			Category:    "owasp",
			Severity:    "high",
			Action:      "block",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Tags:        []string{"xss", "injection", "owasp-top10"},
			HitCount:    0,
		},
		{
			ID:          "rule-003",
			Name:        "文件包含攻击检测",
			Description: "检测本地和远程文件包含攻击",
			RuleBody:    "SecRule ARGS \"@pmFromFile lfi-os-files.data\" \"id:003,phase:2,block,msg:'Local File Inclusion Attack'\"",
			Category:    "owasp",
			Severity:    "medium",
			Action:      "block",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Tags:        []string{"lfi", "rfi", "file-inclusion"},
			HitCount:    0,
		},
		{
			ID:          "rule-004",
			Name:        "命令注入检测",
			Description: "检测操作系统命令注入攻击",
			RuleBody:    "SecRule ARGS \"@pmFromFile unix-shell.data\" \"id:004,phase:2,block,msg:'OS Command Injection Attack'\"",
			Category:    "owasp",
			Severity:    "critical",
			Action:      "block",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Tags:        []string{"command-injection", "rce"},
			HitCount:    0,
		},
		{
			ID:          "rule-005",
			Name:        "恶意User-Agent检测",
			Description: "检测已知恶意的User-Agent字符串",
			RuleBody:    "SecRule REQUEST_HEADERS:User-Agent \"@pmFromFile malicious-ua.data\" \"id:005,phase:1,deny,msg:'Malicious User Agent'\"",
			Category:    "custom",
			Severity:    "medium",
			Action:      "deny",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Tags:        []string{"user-agent", "bot", "scanner"},
			HitCount:    0,
		},
	}

	s.wafRules = append(s.wafRules, defaultRules...)
}

// loadSampleData 加载示例数据
func (s *ModSecurityServer) loadSampleData() {
	// 添加示例攻击日志
	sampleAttacks := []AttackLog{
		{
			ID:           "attack-001",
			Timestamp:    time.Now().Add(-2 * time.Hour),
			SourceIP:     "192.168.1.100",
			TargetURL:    "/admin/login",
			AttackType:   "SQL Injection",
			Severity:     "high",
			RuleID:       "rule-001",
			RuleMessage:  "SQL Injection Attack Detected",
			Action:       "block",
			UserAgent:    "Mozilla/5.0 (compatible; sqlmap/1.4.7)",
			RequestMethod: "POST",
			RequestBody:  "username=admin' OR '1'='1--&password=test",
			ResponseCode: 403,
			Blocked:      true,
			Country:      "CN",
			ASN:          "AS4134",
		},
		{
			ID:           "attack-002",
			Timestamp:    time.Now().Add(-1 * time.Hour),
			SourceIP:     "10.0.0.50",
			TargetURL:    "/search",
			AttackType:   "XSS",
			Severity:     "medium",
			RuleID:       "rule-002",
			RuleMessage:  "XSS Attack Detected",
			Action:       "warn",
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			RequestMethod: "GET",
			RequestBody:  "",
			ResponseCode: 200,
			Blocked:      false,
			Country:      "US",
			ASN:          "AS15169",
		},
	}
	s.attackLogs = append(s.attackLogs, sampleAttacks...)

	// 添加示例被阻止IP
	blockedTime := time.Now().Add(-2 * time.Hour)
	expiresTime := time.Now().Add(22 * time.Hour)
	sampleBlocked := []BlockedIP{
		{
			IP:          "192.168.1.100",
			Reason:      "Multiple SQL injection attempts",
			BlockedAt:   blockedTime,
			ExpiresAt:   &expiresTime,
			AttackCount: 5,
			LastAttack:  blockedTime,
			Country:     "CN",
			ASN:         "AS4134",
			Status:      "active",
		},
	}
	s.blockedIPs = append(s.blockedIPs, sampleBlocked...)
}

// handleMCPRequest 处理MCP请求
func (s *ModSecurityServer) handleMCPRequest(c *gin.Context) {
	var msg mcp.JSONRPCMessage
	if err := c.ShouldBindJSON(&msg); err != nil {
		response := mcp.NewErrorResponse(nil, mcp.ErrorCodeInvalidRequest, "Invalid JSON-RPC request", nil)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	var response *mcp.JSONRPCMessage

	switch msg.Method {
	case mcp.MethodInitialize:
		response = s.handleInitialize(&msg)
	case mcp.MethodListTools:
		response = s.handleListTools(&msg)
	case mcp.MethodCallTool:
		response = s.handleCallTool(&msg)
	case mcp.MethodListResources:
		response = s.handleListResources(&msg)
	case mcp.MethodReadResource:
		response = s.handleReadResource(&msg)
	case mcp.MethodPing:
		response = mcp.NewResponse(msg.ID, map[string]interface{}{"pong": true})
	default:
		response = mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeMethodNotFound, "Method not found", nil)
	}

	c.JSON(http.StatusOK, response)
}

// handleInitialize 处理初始化请求
func (s *ModSecurityServer) handleInitialize(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]interface{}{
			"name":    "modsecurity-mcp-server",
			"version": "1.0.0",
		},
		"capabilities": s.capabilities,
	}
	return mcp.NewResponse(msg.ID, result)
}

// handleListTools 处理列出工具请求
func (s *ModSecurityServer) handleListTools(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"tools": s.tools,
	}
	return mcp.NewResponse(msg.ID, result)
}

// handleCallTool 处理调用工具请求
func (s *ModSecurityServer) handleCallTool(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	params, ok := msg.Params.(map[string]interface{})
	if !ok {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Invalid params", nil)
	}

	toolName, ok := params["name"].(string)
	if !ok {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Tool name is required", nil)
	}

	args, _ := params["arguments"].(map[string]interface{})
	if args == nil {
		args = make(map[string]interface{})
	}

	result, err := s.HandleToolCall(toolName, args)
	if err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInternalError, err.Error(), nil)
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleListResources 处理列出资源请求
func (s *ModSecurityServer) handleListResources(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"resources": s.resources,
	}
	return mcp.NewResponse(msg.ID, result)
}

// handleReadResource 处理读取资源请求
func (s *ModSecurityServer) handleReadResource(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	params, ok := msg.Params.(map[string]interface{})
	if !ok {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Invalid params", nil)
	}

	uri, ok := params["uri"].(string)
	if !ok {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "URI is required", nil)
	}

	contents, err := s.readResource(uri)
	if err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInternalError, err.Error(), nil)
	}

	result := map[string]interface{}{
		"contents": contents,
	}
	return mcp.NewResponse(msg.ID, result)
}

// readResource 读取资源内容
func (s *ModSecurityServer) readResource(uri string) ([]mcp.ResourceContents, error) {
	switch uri {
	case "modsec://config/current":
		data, _ := json.Marshal(s.wafConfig)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "modsec://rules/all":
		data, _ := json.Marshal(s.wafRules)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "modsec://attacks/recent":
		recentAttacks := []AttackLog{}
		for _, attack := range s.attackLogs {
			if attack.Timestamp.After(time.Now().Add(-24 * time.Hour)) {
				recentAttacks = append(recentAttacks, attack)
			}
		}
		data, _ := json.Marshal(recentAttacks)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "modsec://blocked/ips":
		data, _ := json.Marshal(s.blockedIPs)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "modsec://statistics/summary":
		stats := s.generateStatistics()
		data, _ := json.Marshal(stats)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	default:
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
}

// generateStatistics 生成统计信息
func (s *ModSecurityServer) generateStatistics() map[string]interface{} {
	stats := map[string]interface{}{
		"total_attacks":    len(s.attackLogs),
		"blocked_ips":      len(s.blockedIPs),
		"active_rules":     len(s.wafRules),
		"waf_mode":         s.wafConfig.Mode,
		"paranoia_level":   s.wafConfig.ParanoiaLevel,
		"last_24h_attacks": 0,
		"generated_at":     time.Now(),
	}

	// 计算24小时内攻击统计
	for _, attack := range s.attackLogs {
		if attack.Timestamp.After(time.Now().Add(-24 * time.Hour)) {
			stats["last_24h_attacks"] = stats["last_24h_attacks"].(int) + 1
		}
	}

	return stats
}

func main() {
	// 创建ModSecurity服务器
	server := NewModSecurityServer()

	// 设置Gin路由
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":         "healthy",
			"server":         "ModSecurity MCP Server",
			"version":        "1.0.0",
			"modsecurity_version": "3.0.8",
			"waf_mode":       server.wafConfig.Mode,
			"paranoia_level": server.wafConfig.ParanoiaLevel,
			"active_rules":   len(server.wafRules),
			"blocked_ips":    len(server.blockedIPs),
			"time":           time.Now().UTC(),
		})
	})

	// MCP endpoint
	router.POST("/mcp", server.handleMCPRequest)

	// 启动服务器
	srv := &http.Server{
		Addr:    ":8085",
		Handler: router,
	}

	go func() {
		log.Printf("ModSecurity MCP服务器启动在端口 8085")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	})()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭ModSecurity服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("服务器强制关闭:", err)
	}

	log.Println("ModSecurity服务器已退出")
}

// initializeResources 初始化资源
func (s *ModSecurityServer) initializeResources() {
	s.resources = []mcp.Resource{
		{
			URI:         "modsec://config/current",
			Name:        "当前WAF配置",
			Description: "ModSecurity当前配置信息",
			MimeType:    "application/json",
		},
		{
			URI:         "modsec://rules/all",
			Name:        "所有WAF规则",
			Description: "加载的所有ModSecurity规则",
			MimeType:    "application/json",
		},
		{
			URI:         "modsec://attacks/recent",
			Name:        "最近攻击记录",
			Description: "最近24小时的攻击记录",
			MimeType:    "application/json",
		},
		{
			URI:         "modsec://blocked/ips",
			Name:        "被阻止的IP列表",
			Description: "当前被阻止的IP地址列表",
			MimeType:    "application/json",
		},
		{
			URI:         "modsec://statistics/summary",
			Name:        "统计摘要",
			Description: "WAF运行统计和性能摘要",
			MimeType:    "application/json",
		},
		{
			URI:         "modsec://logs/audit",
			Name:        "审计日志",
			Description: "ModSecurity审计日志",
			MimeType:    "text/plain",
		},
	}
}