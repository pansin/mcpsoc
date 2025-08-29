package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// ClamAVServer ClamAV MCP服务器
type ClamAVServer struct {
	capabilities  *mcp.ServerCapabilities
	tools        []mcp.Tool
	resources    []mcp.Resource
	scanHistory  []ScanResult
	quarantine   []QuarantineItem
	virusDB      *VirusDatabase
}

// ScanResult 扫描结果
type ScanResult struct {
	ID          string    `json:"id"`
	FilePath    string    `json:"file_path"`
	FileName    string    `json:"file_name"`
	FileSize    int64     `json:"file_size"`
	ScanTime    time.Time `json:"scan_time"`
	Status      string    `json:"status"`        // clean, infected, error, suspicious
	ThreatName  string    `json:"threat_name"`
	ThreatType  string    `json:"threat_type"`
	Action      string    `json:"action"`        // none, quarantine, delete
	ScanDuration int64    `json:"scan_duration"` // 毫秒
	Scanner     string    `json:"scanner"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// QuarantineItem 隔离项目
type QuarantineItem struct {
	ID           string    `json:"id"`
	OriginalPath string    `json:"original_path"`
	QuarantinePath string  `json:"quarantine_path"`
	ThreatName   string    `json:"threat_name"`
	DetectedAt   time.Time `json:"detected_at"`
	FileHash     string    `json:"file_hash"`
	FileSize     int64     `json:"file_size"`
	Status       string    `json:"status"`       // quarantined, restored, deleted
}

// VirusDatabase 病毒库信息
type VirusDatabase struct {
	Version       string    `json:"version"`
	LastUpdate    time.Time `json:"last_update"`
	SignatureCount int       `json:"signature_count"`
	DatabaseFiles []string  `json:"database_files"`
}

// NewClamAVServer 创建ClamAV服务器
func NewClamAVServer() *ClamAVServer {
	server := &ClamAVServer{
		capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolsCapability{
				ListChanged: false,
			},
			Resources: &mcp.ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
		},
		scanHistory: []ScanResult{},
		quarantine:  []QuarantineItem{},
		virusDB: &VirusDatabase{
			Version:       "1.0.4",
			LastUpdate:    time.Now().Add(-2 * time.Hour),
			SignatureCount: 8500000,
			DatabaseFiles: []string{"main.cvd", "daily.cvd", "bytecode.cvd"},
		},
	}

	server.initializeTools()
	server.initializeResources()
	server.loadSampleData()

	return server
}

// initializeTools 初始化工具
func (s *ClamAVServer) initializeTools() {
	s.tools = []mcp.Tool{
		{
			Name:        "scan_file",
			Description: "扫描单个文件",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"file_path": {
						Type:        "string",
						Description: "要扫描的文件路径",
					},
					"scan_options": {
						Type:        "object",
						Description: "扫描选项",
						Properties: map[string]mcp.JSONSchema{
							"deep_scan": {
								Type:        "boolean",
								Description: "深度扫描模式",
							},
							"detect_pua": {
								Type:        "boolean",
								Description: "检测潜在不需要的应用程序",
							},
							"max_filesize": {
								Type:        "integer",
								Description: "最大文件大小(MB)",
							},
						},
					},
				},
				Required: []string{"file_path"},
			},
		},
		{
			Name:        "scan_directory",
			Description: "扫描目录",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"directory_path": {
						Type:        "string",
						Description: "要扫描的目录路径",
					},
					"recursive": {
						Type:        "boolean",
						Description: "递归扫描子目录",
					},
					"file_types": {
						Type:        "array",
						Description: "指定扫描的文件类型",
						Items:       &mcp.JSONSchema{Type: "string"},
					},
					"exclude_patterns": {
						Type:        "array",
						Description: "排除模式",
						Items:       &mcp.JSONSchema{Type: "string"},
					},
				},
				Required: []string{"directory_path"},
			},
		},
		{
			Name:        "quick_scan",
			Description: "快速系统扫描",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"scan_areas": {
						Type:        "array",
						Description: "扫描区域",
						Items: &mcp.JSONSchema{
							Type: "string",
							Enum: []interface{}{"memory", "startup", "temp", "downloads", "system"},
						},
					},
					"priority": {
						Type:        "string",
						Description: "扫描优先级",
						Enum:        []interface{}{"low", "normal", "high"},
					},
				},
			},
		},
		{
			Name:        "update_database",
			Description: "更新病毒库",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"force_update": {
						Type:        "boolean",
						Description: "强制更新",
					},
					"check_only": {
						Type:        "boolean",
						Description: "只检查更新",
					},
				},
			},
		},
		{
			Name:        "quarantine_file",
			Description: "隔离文件",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"file_path": {
						Type:        "string",
						Description: "要隔离的文件路径",
					},
					"threat_name": {
						Type:        "string",
						Description: "威胁名称",
					},
					"reason": {
						Type:        "string",
						Description: "隔离原因",
					},
				},
				Required: []string{"file_path"},
			},
		},
		{
			Name:        "restore_quarantine",
			Description: "从隔离区恢复文件",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"quarantine_id": {
						Type:        "string",
						Description: "隔离项ID",
					},
					"restore_path": {
						Type:        "string",
						Description: "恢复路径（可选）",
					},
				},
				Required: []string{"quarantine_id"},
			},
		},
		{
			Name:        "get_scan_history",
			Description: "获取扫描历史",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"start_date": {
						Type:        "string",
						Description: "开始日期 (YYYY-MM-DD)",
					},
					"end_date": {
						Type:        "string",
						Description: "结束日期 (YYYY-MM-DD)",
					},
					"status_filter": {
						Type:        "string",
						Description: "状态过滤",
						Enum:        []interface{}{"all", "clean", "infected", "error"},
					},
					"limit": {
						Type:        "integer",
						Description: "结果数量限制",
					},
				},
			},
		},
		{
			Name:        "analyze_malware",
			Description: "分析恶意软件样本",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"file_path": {
						Type:        "string",
						Description: "样本文件路径",
					},
					"analysis_type": {
						Type:        "string",
						Description: "分析类型",
						Enum:        []interface{}{"basic", "detailed", "behavioral"},
					},
					"sandbox": {
						Type:        "boolean",
						Description: "沙箱分析",
					},
				},
				Required: []string{"file_path"},
			},
		},
	}
}

// initializeResources 初始化资源
func (s *ClamAVServer) initializeResources() {
	s.resources = []mcp.Resource{
		{
			URI:         "clamav://database/info",
			Name:        "病毒库信息",
			Description: "ClamAV病毒库的详细信息",
			MimeType:    "application/json",
		},
		{
			URI:         "clamav://scan/history",
			Name:        "扫描历史",
			Description: "最近的文件扫描历史记录",
			MimeType:    "application/json",
		},
		{
			URI:         "clamav://quarantine/list",
			Name:        "隔离文件列表",
			Description: "当前隔离区中的文件列表",
			MimeType:    "application/json",
		},
		{
			URI:         "clamav://statistics/summary",
			Name:        "统计摘要",
			Description: "扫描统计和威胁检测摘要",
			MimeType:    "application/json",
		},
		{
			URI:         "clamav://logs/realtime",
			Name:        "实时日志",
			Description: "ClamAV实时扫描日志",
			MimeType:    "text/plain",
		},
	}
}

// loadSampleData 加载示例数据
func (s *ClamAVServer) loadSampleData() {
	// 添加示例扫描历史
	sampleScans := []ScanResult{
		{
			ID:           "scan-001",
			FilePath:     "/tmp/suspicious.exe",
			FileName:     "suspicious.exe",
			FileSize:     1024000,
			ScanTime:     time.Now().Add(-1 * time.Hour),
			Status:       "infected",
			ThreatName:   "Win.Trojan.Agent-123456",
			ThreatType:   "trojan",
			Action:       "quarantine",
			ScanDuration: 1500,
			Scanner:      "clamav-1.0.4",
		},
		{
			ID:           "scan-002",
			FilePath:     "/home/user/document.pdf",
			FileName:     "document.pdf",
			FileSize:     512000,
			ScanTime:     time.Now().Add(-2 * time.Hour),
			Status:       "clean",
			ThreatName:   "",
			ThreatType:   "",
			Action:       "none",
			ScanDuration: 300,
			Scanner:      "clamav-1.0.4",
		},
	}
	s.scanHistory = append(s.scanHistory, sampleScans...)

	// 添加示例隔离项目
	sampleQuarantine := []QuarantineItem{
		{
			ID:             "quar-001",
			OriginalPath:   "/tmp/suspicious.exe",
			QuarantinePath: "/var/lib/clamav/quarantine/quar-001",
			ThreatName:     "Win.Trojan.Agent-123456",
			DetectedAt:     time.Now().Add(-1 * time.Hour),
			FileHash:       "d41d8cd98f00b204e9800998ecf8427e",
			FileSize:       1024000,
			Status:         "quarantined",
		},
	}
	s.quarantine = append(s.quarantine, sampleQuarantine...)
}

// handleMCPRequest 处理MCP请求
func (s *ClamAVServer) handleMCPRequest(c *gin.Context) {
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
func (s *ClamAVServer) handleInitialize(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]interface{}{
			"name":    "clamav-mcp-server",
			"version": "1.0.0",
		},
		"capabilities": s.capabilities,
	}
	return mcp.NewResponse(msg.ID, result)
}

// handleListTools 处理列出工具请求
func (s *ClamAVServer) handleListTools(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"tools": s.tools,
	}
	return mcp.NewResponse(msg.ID, result)
}

// handleCallTool 处理调用工具请求
func (s *ClamAVServer) handleCallTool(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
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
func (s *ClamAVServer) handleListResources(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := map[string]interface{}{
		"resources": s.resources,
	}
	return mcp.NewResponse(msg.ID, result)
}

// handleReadResource 处理读取资源请求
func (s *ClamAVServer) handleReadResource(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
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
func (s *ClamAVServer) readResource(uri string) ([]mcp.ResourceContents, error) {
	switch uri {
	case "clamav://database/info":
		data, _ := json.Marshal(s.virusDB)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "clamav://scan/history":
		data, _ := json.Marshal(s.scanHistory)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "clamav://quarantine/list":
		data, _ := json.Marshal(s.quarantine)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "clamav://statistics/summary":
		stats := s.generateStatistics()
		data, _ := json.Marshal(stats)
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}}, nil

	case "clamav://logs/realtime":
		logs := s.generateRealtimeLogs()
		return []mcp.ResourceContents{{
			URI:      uri,
			MimeType: "text/plain",
			Text:     logs,
		}}, nil

	default:
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
}

// generateStatistics 生成统计信息
func (s *ClamAVServer) generateStatistics() map[string]interface{} {
	stats := map[string]interface{}{
		"total_scans":     len(s.scanHistory),
		"quarantine_count": len(s.quarantine),
		"database_info":   s.virusDB,
		"scan_statistics": map[string]int{
			"clean":      0,
			"infected":   0,
			"suspicious": 0,
			"error":      0,
		},
		"last_24h_scans": 0,
		"generated_at":    time.Now(),
	}

	// 计算扫描统计
	for _, scan := range s.scanHistory {
		stats["scan_statistics"].(map[string]int)[scan.Status]++
		if scan.ScanTime.After(time.Now().Add(-24 * time.Hour)) {
			stats["last_24h_scans"] = stats["last_24h_scans"].(int) + 1
		}
	}

	return stats
}

// generateRealtimeLogs 生成实时日志
func (s *ClamAVServer) generateRealtimeLogs() string {
	logs := []string{
		fmt.Sprintf("[%s] ClamAV daemon started", time.Now().Format("2006-01-02 15:04:05")),
		fmt.Sprintf("[%s] Database loaded: %d signatures", time.Now().Format("2006-01-02 15:04:05"), s.virusDB.SignatureCount),
		fmt.Sprintf("[%s] Real-time protection enabled", time.Now().Format("2006-01-02 15:04:05")),
	}

	// 添加最近的扫描日志
	for _, scan := range s.scanHistory {
		if scan.ScanTime.After(time.Now().Add(-1 * time.Hour)) {
			logEntry := fmt.Sprintf("[%s] Scanned: %s - Status: %s",
				scan.ScanTime.Format("2006-01-02 15:04:05"),
				scan.FileName,
				scan.Status)
			if scan.Status == "infected" {
				logEntry += fmt.Sprintf(" - Threat: %s", scan.ThreatName)
			}
			logs = append(logs, logEntry)
		}
	}

	return strings.Join(logs, "\n")
}

func main() {
	// 创建ClamAV服务器
	server := NewClamAVServer()

	// 设置Gin路由
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":        "healthy",
			"server":        "ClamAV MCP Server",
			"version":       "1.0.0",
			"clamav_version": "1.0.4",
			"database_version": server.virusDB.Version,
			"last_update":   server.virusDB.LastUpdate,
			"time":          time.Now().UTC(),
		})
	})

	// MCP endpoint
	router.POST("/mcp", server.handleMCPRequest)

	// 启动服务器
	srv := &http.Server{
		Addr:    ":8084",
		Handler: router,
	}

	go func() {
		log.Printf("ClamAV MCP服务器启动在端口 8084")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭ClamAV服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("服务器强制关闭:", err)
	}

	log.Println("ClamAV服务器已退出")
}