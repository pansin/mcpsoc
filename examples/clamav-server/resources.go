package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// handleQuarantineFile 处理文件隔离
func (s *ClamAVServer) handleQuarantineFile(args map[string]interface{}) (*mcp.CallToolResult, error) {
	filePath, ok := args["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("file_path is required")
	}

	reason := "Manual quarantine"
	if r, exists := args["reason"]; exists {
		reason = r.(string)
	}

	// 检查文件是否已在隔离区
	for _, item := range s.quarantine {
		if item.OriginalPath == filePath && item.Status == "quarantined" {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.TextContent{{
					Type: "text",
					Text: fmt.Sprintf("文件已在隔离区: %s", filePath),
				}},
			}, nil
		}
	}

	// 创建隔离项目
	item := QuarantineItem{
		ID:             generateQuarantineID(),
		OriginalPath:   filePath,
		QuarantinePath: fmt.Sprintf("/var/quarantine/%s", generateQuarantineID()),
		ThreatName:     reason,
		DetectedAt:     time.Now(),
		FileHash:       fmt.Sprintf("%x", rand.Int63()),
		FileSize:       int64(rand.Intn(1024*1024) + 1024),
		Status:         "quarantined",
	}

	s.quarantine = append(s.quarantine, item)

	result := map[string]interface{}{
		"status":           "success",
		"quarantine_id":    item.ID,
		"original_path":    item.OriginalPath,
		"quarantine_path":  item.QuarantinePath,
		"quarantined_at":   item.DetectedAt,
		"message":          fmt.Sprintf("文件已成功隔离: %s", filePath),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleRestoreQuarantine 处理从隔离区恢复文件
func (s *ClamAVServer) handleRestoreQuarantine(args map[string]interface{}) (*mcp.CallToolResult, error) {
	quarantineID, ok := args["quarantine_id"].(string)
	if !ok {
		return nil, fmt.Errorf("quarantine_id is required")
	}

	// 查找隔离项目
	var targetItem *QuarantineItem
	var targetIndex int
	for i, item := range s.quarantine {
		if item.ID == quarantineID {
			targetItem = &item
			targetIndex = i
			break
		}
	}

	if targetItem == nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.TextContent{{
				Type: "text",
				Text: fmt.Sprintf("隔离项目未找到: %s", quarantineID),
			}},
		}, nil
	}

	if targetItem.Status != "quarantined" {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.TextContent{{
				Type: "text",
				Text: fmt.Sprintf("隔离项目状态无效: %s (当前状态: %s)", quarantineID, targetItem.Status),
			}},
		}, nil
	}

	// 更新状态
	s.quarantine[targetIndex].Status = "restored"
	restoredAt := time.Now()

	result := map[string]interface{}{
		"status":          "success",
		"quarantine_id":   quarantineID,
		"original_path":   targetItem.OriginalPath,
		"restored_at":     restoredAt,
		"message":         fmt.Sprintf("文件已从隔离区恢复: %s", targetItem.OriginalPath),
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleGetScanHistory 处理获取扫描历史
func (s *ClamAVServer) handleGetScanHistory(args map[string]interface{}) (*mcp.CallToolResult, error) {
	limit := 10
	if l, exists := args["limit"]; exists {
		if lInt, ok := l.(float64); ok {
			limit = int(lInt)
		}
	}

	status := ""
	if st, exists := args["status"]; exists {
		status = st.(string)
	}

	var filteredHistory []ScanResult
	for _, result := range s.scanHistory {
		if status == "" || result.Status == status {
			filteredHistory = append(filteredHistory, result)
		}
	}

	// 限制返回数量
	if len(filteredHistory) > limit {
		filteredHistory = filteredHistory[len(filteredHistory)-limit:]
	}

	summary := map[string]interface{}{
		"total_scans":     len(s.scanHistory),
		"filtered_scans":  len(filteredHistory),
		"scan_history":    filteredHistory,
		"limit":           limit,
		"status_filter":   status,
		"last_scan_time":  nil,
	}

	if len(filteredHistory) > 0 {
		summary["last_scan_time"] = filteredHistory[len(filteredHistory)-1].ScanTime
	}

	// 统计信息
	stats := map[string]int{
		"clean":      0,
		"infected":   0,
		"suspicious": 0,
		"error":      0,
	}

	for _, result := range filteredHistory {
		stats[result.Status]++
	}
	summary["statistics"] = stats

	data, _ := json.Marshal(summary)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleAnalyzeMalware 处理恶意软件分析
func (s *ClamAVServer) handleAnalyzeMalware(args map[string]interface{}) (*mcp.CallToolResult, error) {
	filePath, ok := args["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("file_path is required")
	}

	analysisType := "basic"
	if at, exists := args["analysis_type"]; exists {
		analysisType = at.(string)
	}

	startTime := time.Now()

	// 模拟恶意软件分析
	analysis := s.simulateMalwareAnalysis(filePath, analysisType)
	analysis["analysis_duration"] = time.Since(startTime).Milliseconds()
	analysis["analyzer_version"] = "ClamAV Analysis Engine 1.0"
	analysis["analysis_time"] = time.Now()

	data, _ := json.Marshal(analysis)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// simulateMalwareAnalysis 模拟恶意软件分析
func (s *ClamAVServer) simulateMalwareAnalysis(filePath, analysisType string) map[string]interface{} {
	fileName := strings.ToLower(filePath)
	
	analysis := map[string]interface{}{
		"file_path":     filePath,
		"analysis_type": analysisType,
		"file_info": map[string]interface{}{
			"size":      rand.Intn(1024*1024) + 1024,
			"type":      "Portable Executable",
			"md5":       fmt.Sprintf("%x", rand.Int63()),
			"sha1":      fmt.Sprintf("%x", rand.Int63()),
			"sha256":    fmt.Sprintf("%x", rand.Int63()),
		},
	}

	// 模拟威胁检测
	if strings.Contains(fileName, "virus") || strings.Contains(fileName, "malware") {
		analysis["threat_detected"] = true
		analysis["threat_info"] = map[string]interface{}{
			"threat_name":     "Win32.GenericTrojan",
			"threat_type":     "Trojan",
			"threat_family":   "Generic",
			"confidence":      0.85,
			"severity":        "High",
		}
		
		analysis["behavior_analysis"] = map[string]interface{}{
			"network_activity": []string{
				"连接到可疑域名 evil.com:443",
				"尝试下载额外恶意载荷",
			},
			"file_operations": []string{
				"修改系统注册表",
				"创建隐藏文件",
				"删除系统日志",
			},
			"process_behavior": []string{
				"注入其他进程",
				"提升权限",
				"禁用安全软件",
			},
		}
		
		analysis["ioc_indicators"] = []map[string]interface{}{
			{
				"type":  "domain",
				"value": "evil.com",
				"description": "C&C服务器域名",
			},
			{
				"type":  "ip",
				"value": "192.168.1.100",
				"description": "可疑IP地址",
			},
			{
				"type":  "registry",
				"value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
				"description": "恶意注册表项",
			},
		}
	} else {
		analysis["threat_detected"] = false
		analysis["threat_info"] = nil
		
		analysis["behavior_analysis"] = map[string]interface{}{
			"network_activity": []string{},
			"file_operations":  []string{"正常文件访问"},
			"process_behavior": []string{"正常进程行为"},
		}
		
		analysis["ioc_indicators"] = []map[string]interface{}{}
	}

	// 高级分析选项
	if analysisType == "advanced" {
		analysis["static_analysis"] = map[string]interface{}{
			"pe_structure":    "正常",
			"entropy":         3.2,
			"packed":          false,
			"digital_signature": false,
			"imports": []string{
				"kernel32.dll",
				"user32.dll",
				"ntdll.dll",
			},
		}
		
		analysis["dynamic_analysis"] = map[string]interface{}{
			"sandbox_executed": true,
			"execution_time":   30000,
			"cpu_usage":        "Normal",
			"memory_usage":     "Low",
			"dropped_files":    []string{},
		}
	}

	return analysis
}

// ListTools 列出所有可用工具
func (s *ClamAVServer) ListTools() ([]mcp.Tool, error) {
	return s.tools, nil
}

// ListResources 列出所有可用资源
func (s *ClamAVServer) ListResources() ([]mcp.Resource, error) {
	return s.resources, nil
}

// GetCapabilities 获取服务器能力
func (s *ClamAVServer) GetCapabilities() *mcp.ServerCapabilities {
	return s.capabilities
}

// loadSampleData 加载示例数据
func (s *ClamAVServer) loadSampleData() {
	// 添加一些示例扫描历史
	sampleScans := []ScanResult{
		{
			ID:           "scan_001",
			FilePath:     "/tmp/testfile.txt",
			FileName:     "testfile.txt",
			FileSize:     1024,
			ScanTime:     time.Now().Add(-2 * time.Hour),
			Status:       "clean",
			ThreatName:   "",
			ThreatType:   "",
			Action:       "none",
			ScanDuration: 150,
			Scanner:      "ClamAV 1.0.4",
			Metadata: map[string]interface{}{
				"file_type": ".txt",
			},
		},
		{
			ID:           "scan_002",
			FilePath:     "/downloads/suspicious.exe",
			FileName:     "suspicious.exe",
			FileSize:     512000,
			ScanTime:     time.Now().Add(-1 * time.Hour),
			Status:       "infected",
			ThreatName:   "Win32.TestVirus",
			ThreatType:   "Trojan",
			Action:       "quarantine",
			ScanDuration: 500,
			Scanner:      "ClamAV 1.0.4",
			Metadata: map[string]interface{}{
				"file_type": ".exe",
			},
		},
	}

	s.scanHistory = append(s.scanHistory, sampleScans...)

	// 添加示例隔离项目
	sampleQuarantine := []QuarantineItem{
		{
			ID:             "quar_001",
			OriginalPath:   "/downloads/suspicious.exe",
			QuarantinePath: "/var/quarantine/quar_001",
			ThreatName:     "Win32.TestVirus",
			DetectedAt:     time.Now().Add(-1 * time.Hour),
			FileHash:       "a1b2c3d4e5f6",
			FileSize:       512000,
			Status:         "quarantined",
		},
	}

	s.quarantine = append(s.quarantine, sampleQuarantine...)
}