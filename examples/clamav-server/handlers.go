package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// HandleToolCall 处理工具调用
func (s *ClamAVServer) HandleToolCall(name string, arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	switch name {
	case "scan_file":
		return s.handleScanFile(arguments)
	case "scan_directory":
		return s.handleScanDirectory(arguments)
	case "quick_scan":
		return s.handleQuickScan(arguments)
	case "update_database":
		return s.handleUpdateDatabase(arguments)
	case "quarantine_file":
		return s.handleQuarantineFile(arguments)
	case "restore_quarantine":
		return s.handleRestoreQuarantine(arguments)
	case "get_scan_history":
		return s.handleGetScanHistory(arguments)
	case "analyze_malware":
		return s.handleAnalyzeMalware(arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

// handleScanFile 处理文件扫描
func (s *ClamAVServer) handleScanFile(args map[string]interface{}) (*mcp.CallToolResult, error) {
	filePath, ok := args["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("file_path is required")
	}

	// 检查文件是否存在
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.TextContent{{
				Type: "text",
				Text: fmt.Sprintf("文件不存在或无法访问: %s", err.Error()),
			}},
		}, nil
	}

	startTime := time.Now()
	
	// 模拟病毒扫描
	result := s.simulateFileScan(filePath, fileInfo)
	result.ScanDuration = time.Since(startTime).Milliseconds()
	
	// 保存到扫描历史
	s.scanHistory = append(s.scanHistory, result)

	// 如果检测到威胁且需要隔离
	if result.Status == "infected" && result.Action == "quarantine" {
		s.quarantineFile(result)
	}

	response := map[string]interface{}{
		"scan_result": result,
		"status":      "success",
		"message":     fmt.Sprintf("文件扫描完成: %s", result.Status),
	}

	data, _ := json.Marshal(response)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleScanDirectory 处理目录扫描
func (s *ClamAVServer) handleScanDirectory(args map[string]interface{}) (*mcp.CallToolResult, error) {
	dirPath, ok := args["directory_path"].(string)
	if !ok {
		return nil, fmt.Errorf("directory_path is required")
	}

	recursive := false
	if r, exists := args["recursive"]; exists {
		recursive = r.(bool)
	}

	var fileTypes []string
	if ft, exists := args["file_types"]; exists {
		for _, t := range ft.([]interface{}) {
			fileTypes = append(fileTypes, t.(string))
		}
	}

	startTime := time.Now()
	results := []ScanResult{}
	
	// 扫描目录
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 忽略错误，继续扫描
		}

		if info.IsDir() && !recursive && path != dirPath {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			// 检查文件类型过滤
			if len(fileTypes) > 0 {
				ext := strings.TrimPrefix(filepath.Ext(path), ".")
				found := false
				for _, ft := range fileTypes {
					if ext == ft {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			}

			result := s.simulateFileScan(path, info)
			results = append(results, result)
			s.scanHistory = append(s.scanHistory, result)

			if result.Status == "infected" && result.Action == "quarantine" {
				s.quarantineFile(result)
			}
		}
		return nil
	})

	summary := map[string]interface{}{
		"total_files":    len(results),
		"clean_files":    0,
		"infected_files": 0,
		"suspicious_files": 0,
		"error_files":    0,
		"scan_duration":  time.Since(startTime).Milliseconds(),
		"directory":      dirPath,
		"results":        results,
	}

	// 统计结果
	for _, result := range results {
		switch result.Status {
		case "clean":
			summary["clean_files"] = summary["clean_files"].(int) + 1
		case "infected":
			summary["infected_files"] = summary["infected_files"].(int) + 1
		case "suspicious":
			summary["suspicious_files"] = summary["suspicious_files"].(int) + 1
		case "error":
			summary["error_files"] = summary["error_files"].(int) + 1
		}
	}

	if err != nil {
		summary["error"] = err.Error()
	}

	data, _ := json.Marshal(summary)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleQuickScan 处理快速扫描
func (s *ClamAVServer) handleQuickScan(args map[string]interface{}) (*mcp.CallToolResult, error) {
	scanAreas := []string{"memory", "startup", "temp"}
	if areas, exists := args["scan_areas"]; exists {
		scanAreas = []string{}
		for _, area := range areas.([]interface{}) {
			scanAreas = append(scanAreas, area.(string))
		}
	}

	priority := "normal"
	if p, exists := args["priority"]; exists {
		priority = p.(string)
	}

	startTime := time.Now()
	results := map[string]interface{}{
		"scan_type":    "quick_scan",
		"scan_areas":   scanAreas,
		"priority":     priority,
		"start_time":   startTime,
		"threats_found": 0,
		"files_scanned": 0,
		"areas_scanned": map[string]interface{}{},
	}

	// 模拟各区域扫描
	totalFiles := 0
	threatsFound := 0
	
	for _, area := range scanAreas {
		areaResult := s.simulateAreaScan(area)
		results["areas_scanned"].(map[string]interface{})[area] = areaResult
		totalFiles += areaResult["files_scanned"].(int)
		threatsFound += areaResult["threats_found"].(int)
	}

	results["files_scanned"] = totalFiles
	results["threats_found"] = threatsFound
	results["scan_duration"] = time.Since(startTime).Milliseconds()
	results["end_time"] = time.Now()
	results["status"] = "completed"

	if threatsFound > 0 {
		results["recommendation"] = "发现威胁，建议进行完整系统扫描"
	} else {
		results["recommendation"] = "系统状态良好"
	}

	data, _ := json.Marshal(results)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// handleUpdateDatabase 处理病毒库更新
func (s *ClamAVServer) handleUpdateDatabase(args map[string]interface{}) (*mcp.CallToolResult, error) {
	forceUpdate := false
	if f, exists := args["force_update"]; exists {
		forceUpdate = f.(bool)
	}

	checkOnly := false
	if c, exists := args["check_only"]; exists {
		checkOnly = c.(bool)
	}

	currentVersion := s.virusDB.Version
	newVersion := "1.0.5" // 模拟新版本

	result := map[string]interface{}{
		"current_version": currentVersion,
		"available_version": newVersion,
		"last_update": s.virusDB.LastUpdate,
		"update_needed": currentVersion != newVersion,
	}

	if checkOnly {
		result["action"] = "check_only"
		result["message"] = "检查更新完成"
	} else {
		if forceUpdate || currentVersion != newVersion {
			// 模拟更新过程
			result["action"] = "update_performed"
			result["update_start"] = time.Now()
			
			// 更新病毒库信息
			s.virusDB.Version = newVersion
			s.virusDB.LastUpdate = time.Now()
			s.virusDB.SignatureCount += 50000 // 模拟新增签名
			
			result["update_end"] = time.Now()
			result["new_signatures"] = 50000
			result["total_signatures"] = s.virusDB.SignatureCount
			result["message"] = "病毒库更新成功"
		} else {
			result["action"] = "no_update_needed"
			result["message"] = "病毒库已是最新版本"
		}
	}

	data, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.TextContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

// simulateFileScan 模拟文件扫描
func (s *ClamAVServer) simulateFileScan(filePath string, fileInfo os.FileInfo) ScanResult {
	result := ScanResult{
		ID:       generateScanID(),
		FilePath: filePath,
		FileName: fileInfo.Name(),
		FileSize: fileInfo.Size(),
		ScanTime: time.Now(),
		Scanner:  "ClamAV 1.0.4",
		Metadata: map[string]interface{}{
			"file_type": filepath.Ext(filePath),
			"modified":  fileInfo.ModTime(),
		},
	}

	// 模拟威胁检测逻辑
	fileName := strings.ToLower(fileInfo.Name())
	if strings.Contains(fileName, "virus") || strings.Contains(fileName, "malware") || 
	   strings.Contains(fileName, "trojan") || strings.HasSuffix(fileName, ".exe.txt") {
		result.Status = "infected"
		result.ThreatName = "Win32.TestVirus"
		result.ThreatType = "Trojan"
		result.Action = "quarantine"
	} else if strings.Contains(fileName, "suspicious") || fileInfo.Size() > 100*1024*1024 {
		result.Status = "suspicious"
		result.ThreatName = ""
		result.ThreatType = "Suspicious"
		result.Action = "none"
	} else {
		result.Status = "clean"
		result.Action = "none"
	}

	return result
}

// simulateAreaScan 模拟区域扫描
func (s *ClamAVServer) simulateAreaScan(area string) map[string]interface{} {
	rand.Seed(time.Now().UnixNano())
	
	var filesScanned, threatsFound int
	var scanTime time.Duration
	
	switch area {
	case "memory":
		filesScanned = rand.Intn(500) + 100
		threatsFound = rand.Intn(3)
		scanTime = time.Duration(rand.Intn(5)+1) * time.Second
	case "startup":
		filesScanned = rand.Intn(50) + 10
		threatsFound = rand.Intn(2)
		scanTime = time.Duration(rand.Intn(3)+1) * time.Second
	case "temp":
		filesScanned = rand.Intn(1000) + 200
		threatsFound = rand.Intn(5)
		scanTime = time.Duration(rand.Intn(10)+2) * time.Second
	case "downloads":
		filesScanned = rand.Intn(200) + 50
		threatsFound = rand.Intn(3)
		scanTime = time.Duration(rand.Intn(7)+2) * time.Second
	case "system":
		filesScanned = rand.Intn(2000) + 500
		threatsFound = rand.Intn(2)
		scanTime = time.Duration(rand.Intn(15)+5) * time.Second
	}

	return map[string]interface{}{
		"area":           area,
		"files_scanned":  filesScanned,
		"threats_found":  threatsFound,
		"scan_duration":  scanTime.Milliseconds(),
		"status":        "completed",
	}
}

// quarantineFile 隔离文件
func (s *ClamAVServer) quarantineFile(result ScanResult) error {
	item := QuarantineItem{
		ID:           generateQuarantineID(),
		OriginalPath: result.FilePath,
		QuarantinePath: fmt.Sprintf("/var/quarantine/%s", generateQuarantineID()),
		ThreatName:   result.ThreatName,
		DetectedAt:   result.ScanTime,
		FileHash:     fmt.Sprintf("%x", md5.Sum([]byte(result.FilePath))),
		FileSize:     result.FileSize,
		Status:       "quarantined",
	}
	
	s.quarantine = append(s.quarantine, item)
	return nil
}

// generateScanID 生成扫描ID
func generateScanID() string {
	return fmt.Sprintf("scan_%d_%d", time.Now().Unix(), rand.Intn(10000))
}

// generateQuarantineID 生成隔离ID
func generateQuarantineID() string {
	return fmt.Sprintf("quar_%d_%d", time.Now().Unix(), rand.Intn(10000))
}