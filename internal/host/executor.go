package host

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/sirupsen/logrus"
)

// ParallelExecutor 并行执行器
type ParallelExecutor struct {
	mcpManager *mcp.Manager
	logger     *logrus.Logger
	maxWorkers int
}

// NewParallelExecutor 创建新的并行执行器
func NewParallelExecutor(mcpManager *mcp.Manager, logger *logrus.Logger) *ParallelExecutor {
	return &ParallelExecutor{
		mcpManager: mcpManager,
		logger:     logger,
		maxWorkers: 10, // 默认最大10个并发工作器
	}
}

// EnhancedExecutor 增强执行器
type EnhancedExecutor struct {
	parallelExecutor *ParallelExecutor
	logger           *logrus.Logger
	constraints      *QueryConstraints
}

// NewEnhancedExecutor 创建增强执行器
func NewEnhancedExecutor(parallelExecutor *ParallelExecutor, logger *logrus.Logger) *EnhancedExecutor {
	return &EnhancedExecutor{
		parallelExecutor: parallelExecutor,
		logger:           logger,
	}
}

// SetConstraints 设置执行约束
func (ee *EnhancedExecutor) SetConstraints(constraints *QueryConstraints) {
	ee.constraints = constraints
	if constraints.MaxConcurrency > 0 {
		ee.parallelExecutor.maxWorkers = constraints.MaxConcurrency
	}
}

// ExecuteStage 执行阶段
func (ee *EnhancedExecutor) ExecuteStage(ctx context.Context, stage *ExecutionStage) (*StageResult, error) {
	ee.logger.WithFields(logrus.Fields{
		"stage_id":   stage.ID,
		"stage_name": stage.Name,
		"stage_type": stage.Type,
		"tool_count": len(stage.Tools),
	}).Info("Executing stage")

	startTime := time.Now()

	result := &StageResult{
		StageID:       stage.ID,
		Status:        "running",
		SourceResults: make(map[string]*SourceResult),
		StartTime:     startTime,
	}

	if stage.Type == "parallel" {
		err := ee.executeParallel(ctx, stage, result)
		if err != nil {
			result.Status = "failed"
			result.Error = err.Error()
			return result, err
		}
	} else {
		err := ee.executeSequential(ctx, stage, result)
		if err != nil {
			result.Status = "failed"
			result.Error = err.Error()
			return result, err
		}
	}

	result.Status = "completed"
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)
	result.ToolCallCount = len(stage.Tools)

	ee.logger.WithFields(logrus.Fields{
		"stage_id": stage.ID,
		"duration": result.Duration,
		"status":   result.Status,
	}).Info("Stage execution completed")

	return result, nil
}

// executeParallel 并行执行工具
func (ee *EnhancedExecutor) executeParallel(ctx context.Context, stage *ExecutionStage, result *StageResult) error {
	var wg sync.WaitGroup
	resultChan := make(chan *ToolResult, len(stage.Tools))
	errorChan := make(chan error, len(stage.Tools))
	
	// 创建工作器池
	workerCount := ee.parallelExecutor.maxWorkers
	if len(stage.Tools) < workerCount {
		workerCount = len(stage.Tools)
	}

	toolChan := make(chan ToolExecution, len(stage.Tools))
	
	// 启动工作器
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tool := range toolChan {
				toolResult, err := ee.executeTool(ctx, &tool)
				if err != nil {
					select {
					case errorChan <- err:
					case <-ctx.Done():
						return
					}
				} else {
					select {
					case resultChan <- toolResult:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// 发送工具到工作器
	go func() {
		defer close(toolChan)
		for _, tool := range stage.Tools {
			select {
			case toolChan <- tool:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 等待所有工作器完成
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// 收集结果
	var errors []error
	for {
		select {
		case toolResult, ok := <-resultChan:
			if !ok {
				resultChan = nil
			} else {
				ee.addToolResultToStage(result, toolResult)
			}
		case err, ok := <-errorChan:
			if !ok {
				errorChan = nil
			} else {
				errors = append(errors, err)
				ee.logger.WithError(err).Warn("Tool execution failed in parallel stage")
			}
		case <-ctx.Done():
			return ctx.Err()
		}

		if resultChan == nil && errorChan == nil {
			break
		}
	}

	// 如果有错误且不允许失败安全，返回错误
	if len(errors) > 0 && !stage.CanFailSafe {
		return fmt.Errorf("parallel execution failed with %d errors: %v", len(errors), errors[0])
	}

	return nil
}

// executeSequential 串行执行工具
func (ee *EnhancedExecutor) executeSequential(ctx context.Context, stage *ExecutionStage, result *StageResult) error {
	for _, tool := range stage.Tools {
		toolResult, err := ee.executeTool(ctx, &tool)
		if err != nil {
			ee.logger.WithError(err).WithField("tool", tool.ToolName).Warn("Tool execution failed in sequential stage")
			
			if tool.FailureMode == "abort" || !stage.CanFailSafe {
				return fmt.Errorf("tool %s failed: %w", tool.ToolName, err)
			}
			// 如果是continue模式，继续执行下一个工具
			continue
		}

		ee.addToolResultToStage(result, toolResult)

		// 检查上下文是否被取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	return nil
}

// executeTool 执行单个工具
func (ee *EnhancedExecutor) executeTool(ctx context.Context, tool *ToolExecution) (*ToolResult, error) {
	ee.logger.WithFields(logrus.Fields{
		"server_id": tool.ServerID,
		"tool_name": tool.ToolName,
		"timeout":   tool.Timeout,
	}).Debug("Executing tool")

	// 创建带超时的上下文
	toolCtx, cancel := context.WithTimeout(ctx, tool.Timeout)
	defer cancel()

	startTime := time.Now()

	// 执行工具调用
	var result interface{}
	var err error

	for attempt := 0; attempt <= tool.RetryCount; attempt++ {
		if attempt > 0 {
			ee.logger.WithFields(logrus.Fields{
				"tool_name": tool.ToolName,
				"attempt":   attempt + 1,
			}).Debug("Retrying tool execution")

			// 重试延迟
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-toolCtx.Done():
				return nil, toolCtx.Err()
			}
		}

		result, err = ee.parallelExecutor.mcpManager.CallTool(toolCtx, tool.ServerID, tool.ToolName, tool.Arguments)
		if err == nil {
			break
		}

		ee.logger.WithError(err).WithFields(logrus.Fields{
			"tool_name": tool.ToolName,
			"attempt":   attempt + 1,
		}).Warn("Tool execution attempt failed")
	}

	duration := time.Since(startTime)

	toolResult := &ToolResult{
		ServerID:  tool.ServerID,
		ToolName:  tool.ToolName,
		Arguments: tool.Arguments,
		Result:    result,
		Duration:  duration,
		Success:   err == nil,
		Timestamp: time.Now(),
	}

	if err != nil {
		toolResult.Error = err.Error()
		return toolResult, err
	}

	ee.logger.WithFields(logrus.Fields{
		"tool_name": tool.ToolName,
		"duration":  duration,
	}).Debug("Tool execution completed successfully")

	return toolResult, nil
}

// addToolResultToStage 添加工具结果到阶段结果
func (ee *EnhancedExecutor) addToolResultToStage(stageResult *StageResult, toolResult *ToolResult) {
	if stageResult.SourceResults[toolResult.ServerID] == nil {
		stageResult.SourceResults[toolResult.ServerID] = &SourceResult{
			Data:      []interface{}{},
			Success:   true,
			Timestamp: time.Now(),
		}
	}

	sourceResult := stageResult.SourceResults[toolResult.ServerID]
	
	// 添加工具结果数据
	sourceResult.Data = append(sourceResult.Data, map[string]interface{}{
		"tool":      toolResult.ToolName,
		"result":    toolResult.Result,
		"duration":  toolResult.Duration,
		"timestamp": toolResult.Timestamp,
	})

	// 如果工具执行失败，标记源结果为失败
	if !toolResult.Success {
		sourceResult.Success = false
		sourceResult.Error = toolResult.Error
	}

	sourceResult.Timestamp = time.Now()
}

// EnhancedResults 增强结果
type EnhancedResults struct {
	Sources        map[string]*SourceResult `json:"sources"`
	TotalToolCalls int                      `json:"total_tool_calls"`
	TotalDuration  time.Duration            `json:"total_duration"`
	SuccessRate    float64                  `json:"success_rate"`
	StartTime      time.Time                `json:"start_time"`
	EndTime        time.Time                `json:"end_time"`
}

// StageResult 阶段结果
type StageResult struct {
	StageID       string                   `json:"stage_id"`
	Status        string                   `json:"status"`
	SourceResults map[string]*SourceResult `json:"source_results"`
	ToolCallCount int                      `json:"tool_call_count"`
	Duration      time.Duration            `json:"duration"`
	StartTime     time.Time                `json:"start_time"`
	EndTime       time.Time                `json:"end_time"`
	Error         string                   `json:"error,omitempty"`
}

// SourceResult 数据源结果
type SourceResult struct {
	Data      []interface{} `json:"data"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// ToolResult 工具执行结果
type ToolResult struct {
	ServerID  string                 `json:"server_id"`
	ToolName  string                 `json:"tool_name"`
	Arguments map[string]interface{} `json:"arguments"`
	Result    interface{}            `json:"result"`
	Duration  time.Duration          `json:"duration"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}