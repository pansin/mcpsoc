package host

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/ai"
	"github.com/sirupsen/logrus"
)

// IntelligentRecommendations 智能推荐
type IntelligentRecommendations struct {
	Immediate []Recommendation  `json:"immediate"`
	ShortTerm []Recommendation  `json:"short_term"`
	LongTerm  []Recommendation  `json:"long_term"`
	Insights  []AnalysisInsight `json:"insights"`
}

// Recommendation 推荐建议
type Recommendation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority"`
	Impact      string                 `json:"impact"`
	Actions     []RecommendedAction    `json:"actions"`
	Context     map[string]interface{} `json:"context"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
}

// RecommendedAction 推荐行动
type RecommendedAction struct {
	ActionID    string                 `json:"action_id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Command     string                 `json:"command,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Automated   bool                   `json:"automated"`
	Urgent      bool                   `json:"urgent"`
	Estimated   time.Duration          `json:"estimated_duration"`
}

// RecommendationEngine 推荐引擎
type RecommendationEngine struct {
	logger    *logrus.Logger
	aiService ai.Service
	rules     []*RecommendationRule
}

// NewRecommendationEngine 创建推荐引擎
func NewRecommendationEngine(logger *logrus.Logger, aiService ai.Service) *RecommendationEngine {
	engine := &RecommendationEngine{
		logger:    logger,
		aiService: aiService,
		rules:     []*RecommendationRule{},
	}

	// 初始化内置规则
	engine.initializeBuiltinRules()
	
	return engine
}

// GenerateRecommendations 生成推荐
func (re *RecommendationEngine) GenerateRecommendations(ctx context.Context, query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult) (*IntelligentRecommendations, error) {
	re.logger.WithFields(logrus.Fields{
		"query_id": query.ID,
		"intent":   query.Intent,
	}).Info("Generating intelligent recommendations")

	recommendations := &IntelligentRecommendations{
		Immediate: []Recommendation{},
		ShortTerm: []Recommendation{},
		LongTerm:  []Recommendation{},
		Insights:  []AnalysisInsight{},
	}

	// 基于规则生成推荐
	re.generateRuleBasedRecommendations(query, results, correlatedData, recommendations)

	// 基于威胁模式生成推荐
	re.generateThreatPatternRecommendations(correlatedData, recommendations)

	// 基于数据关联生成推荐
	re.generateCorrelationRecommendations(correlatedData, recommendations)

	// 基于系统性能生成推荐
	re.generatePerformanceRecommendations(results, recommendations)

	// 使用AI增强推荐
	if re.aiService != nil {
		err := re.enhanceWithAI(ctx, query, results, correlatedData, recommendations)
		if err != nil {
			re.logger.WithError(err).Warn("Failed to enhance recommendations with AI")
		}
	}

	// 生成分析洞察
	re.generateAnalysisInsights(query, results, correlatedData, recommendations)

	re.logger.WithFields(logrus.Fields{
		"immediate_count": len(recommendations.Immediate),
		"short_term_count": len(recommendations.ShortTerm),
		"long_term_count": len(recommendations.LongTerm),
		"insights_count": len(recommendations.Insights),
	}).Info("Recommendations generated")

	return recommendations, nil
}

// generateRuleBasedRecommendations 基于规则生成推荐
func (re *RecommendationEngine) generateRuleBasedRecommendations(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult, recommendations *IntelligentRecommendations) {
	for _, rule := range re.rules {
		if rule.ShouldApply(query, results, correlatedData) {
			recommendation := rule.GenerateRecommendation(query, results, correlatedData)
			if recommendation != nil {
				switch recommendation.Priority {
				case "critical", "high":
					recommendations.Immediate = append(recommendations.Immediate, *recommendation)
				case "medium":
					recommendations.ShortTerm = append(recommendations.ShortTerm, *recommendation)
				case "low":
					recommendations.LongTerm = append(recommendations.LongTerm, *recommendation)
				}
			}
		}
	}
}

// generateThreatPatternRecommendations 基于威胁模式生成推荐
func (re *RecommendationEngine) generateThreatPatternRecommendations(correlatedData *CorrelationResult, recommendations *IntelligentRecommendations) {
	if correlatedData == nil {
		return
	}

	for _, pattern := range correlatedData.Patterns {
		rec := Recommendation{
			ID:          fmt.Sprintf("threat_%s", pattern.PatternID),
			Type:        "threat_response",
			Title:       fmt.Sprintf("威胁模式响应: %s", pattern.Name),
			Description: pattern.Description,
			Priority:    re.mapSeverityToPriority(pattern.Severity),
			Impact:      pattern.Severity,
			Confidence:  pattern.Confidence,
			Timestamp:   time.Now(),
			Context: map[string]interface{}{
				"pattern_id": pattern.PatternID,
				"indicators": pattern.Indicators,
			},
		}

		// 根据威胁类型生成具体行动
		rec.Actions = re.generateThreatActions(pattern)

		switch rec.Priority {
		case "critical", "high":
			recommendations.Immediate = append(recommendations.Immediate, rec)
		case "medium":
			recommendations.ShortTerm = append(recommendations.ShortTerm, rec)
		default:
			recommendations.LongTerm = append(recommendations.LongTerm, rec)
		}
	}
}

// generateCorrelationRecommendations 基于数据关联生成推荐
func (re *RecommendationEngine) generateCorrelationRecommendations(correlatedData *CorrelationResult, recommendations *IntelligentRecommendations) {
	if correlatedData == nil || len(correlatedData.Correlations) == 0 {
		return
	}

	// 如果发现多个关联，建议进一步调查
	if len(correlatedData.Correlations) > 3 {
		rec := Recommendation{
			ID:          "correlation_investigation",
			Type:        "investigation",
			Title:       "深度关联调查",
			Description: fmt.Sprintf("发现 %d 个数据关联模式，建议进行深度调查", len(correlatedData.Correlations)),
			Priority:    "medium",
			Impact:      "medium",
			Confidence:  0.7,
			Timestamp:   time.Now(),
			Actions: []RecommendedAction{
				{
					ActionID:    "expand_investigation",
					Type:        "investigation",
					Title:       "扩展调查范围",
					Description: "扩大时间窗口和数据源范围进行调查",
					Automated:   false,
					Urgent:      false,
					Estimated:   30 * time.Minute,
				},
			},
		}
		recommendations.ShortTerm = append(recommendations.ShortTerm, rec)
	}
}

// generatePerformanceRecommendations 基于系统性能生成推荐
func (re *RecommendationEngine) generatePerformanceRecommendations(results *EnhancedResults, recommendations *IntelligentRecommendations) {
	// 如果成功率低，建议检查系统
	if results.SuccessRate < 0.8 {
		rec := Recommendation{
			ID:          "system_health_check",
			Type:        "system_maintenance",
			Title:       "系统健康检查",
			Description: fmt.Sprintf("查询成功率为 %.1f%%，建议检查MCP服务器状态", results.SuccessRate*100),
			Priority:    "medium",
			Impact:      "medium",
			Confidence:  0.8,
			Timestamp:   time.Now(),
			Actions: []RecommendedAction{
				{
					ActionID:    "check_mcp_servers",
					Type:        "diagnostic",
					Title:       "检查MCP服务器",
					Description: "验证所有MCP服务器的连接状态和健康度",
					Automated:   true,
					Urgent:      false,
					Estimated:   5 * time.Minute,
				},
			},
		}
		recommendations.ShortTerm = append(recommendations.ShortTerm, rec)
	}

	// 如果执行时间过长，建议优化
	if results.TotalDuration > 5*time.Minute {
		rec := Recommendation{
			ID:          "performance_optimization",
			Type:        "optimization",
			Title:       "性能优化",
			Description: fmt.Sprintf("查询执行时间为 %v，建议优化查询性能", results.TotalDuration),
			Priority:    "low",
			Impact:      "medium",
			Confidence:  0.6,
			Timestamp:   time.Now(),
			Actions: []RecommendedAction{
				{
					ActionID:    "optimize_queries",
					Type:        "optimization",
					Title:       "优化查询策略",
					Description: "分析慢查询并优化执行计划",
					Automated:   false,
					Urgent:      false,
					Estimated:   2 * time.Hour,
				},
			},
		}
		recommendations.LongTerm = append(recommendations.LongTerm, rec)
	}
}

// enhanceWithAI 使用AI增强推荐
func (re *RecommendationEngine) enhanceWithAI(ctx context.Context, query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult, recommendations *IntelligentRecommendations) error {
	// 构建AI增强提示
	prompt := re.buildEnhancementPrompt(query, results, correlatedData, recommendations)
	
	aiReq := &ai.QueryRequest{
		Type:    ai.QueryTypeNaturalLanguage,
		Query:   prompt,
		Context: query.Context,
	}

	aiResp, err := re.aiService.Query(ctx, aiReq)
	if err != nil {
		return err
	}

	// 解析AI响应并增强推荐
	return re.parseAndEnhanceRecommendations(aiResp.Response, recommendations)
}

// generateAnalysisInsights 生成分析洞察
func (re *RecommendationEngine) generateAnalysisInsights(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult, recommendations *IntelligentRecommendations) {
	// 数据源覆盖洞察
	if len(results.Sources) > 1 {
		insight := AnalysisInsight{
			InsightID:   "data_source_coverage",
			Type:        "coverage_analysis",
			Title:       "数据源覆盖分析",
			Description: fmt.Sprintf("查询涵盖了 %d 个数据源，具有良好的数据覆盖度", len(results.Sources)),
			Confidence:  0.8,
			Impact:      "medium",
			Timestamp:   time.Now(),
		}
		recommendations.Insights = append(recommendations.Insights, insight)
	}

	// 威胁检测洞察
	if correlatedData != nil && len(correlatedData.Patterns) > 0 {
		highSeverityPatterns := 0
		for _, pattern := range correlatedData.Patterns {
			if pattern.Severity == "high" || pattern.Severity == "critical" {
				highSeverityPatterns++
			}
		}

		if highSeverityPatterns > 0 {
			insight := AnalysisInsight{
				InsightID:   "threat_detection_insight",
				Type:        "threat_analysis",
				Title:       "威胁检测洞察",
				Description: fmt.Sprintf("检测到 %d 个高危威胁模式，需要立即关注", highSeverityPatterns),
				Confidence:  0.9,
				Impact:      "high",
				Timestamp:   time.Now(),
			}
			recommendations.Insights = append(recommendations.Insights, insight)
		}
	}

	// 关联分析洞察
	if correlatedData != nil && len(correlatedData.Correlations) > 0 {
		insight := AnalysisInsight{
			InsightID:   "correlation_insight",
			Type:        "correlation_analysis",
			Title:       "关联分析洞察",
			Description: fmt.Sprintf("发现 %d 个数据关联，可能存在潜在的攻击链", len(correlatedData.Correlations)),
			Confidence:  0.7,
			Impact:      "medium",
			Timestamp:   time.Now(),
		}
		recommendations.Insights = append(recommendations.Insights, insight)
	}
}

// 辅助方法

func (re *RecommendationEngine) mapSeverityToPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func (re *RecommendationEngine) generateThreatActions(pattern ThreatPattern) []RecommendedAction {
	var actions []RecommendedAction

	switch pattern.Type {
	case "port_scan":
		actions = append(actions, RecommendedAction{
			ActionID:    "block_scanning_ip",
			Type:        "blocking",
			Title:       "阻止扫描IP",
			Description: "在防火墙中阻止可疑IP地址",
			Automated:   true,
			Urgent:      true,
			Estimated:   2 * time.Minute,
		})
	case "brute_force":
		actions = append(actions, RecommendedAction{
			ActionID:    "account_lockout",
			Type:        "protection",
			Title:       "账户锁定",
			Description: "临时锁定被攻击的用户账户",
			Automated:   true,
			Urgent:      true,
			Estimated:   1 * time.Minute,
		})
	case "malware_communication":
		actions = append(actions, RecommendedAction{
			ActionID:    "block_malicious_domain",
			Type:        "blocking",
			Title:       "阻止恶意域名",
			Description: "在DNS或防火墙中阻止恶意域名",
			Automated:   true,
			Urgent:      true,
			Estimated:   3 * time.Minute,
		})
	default:
		actions = append(actions, RecommendedAction{
			ActionID:    "manual_investigation",
			Type:        "investigation",
			Title:       "人工调查",
			Description: "需要安全分析师进行人工调查",
			Automated:   false,
			Urgent:      false,
			Estimated:   30 * time.Minute,
		})
	}

	return actions
}

func (re *RecommendationEngine) buildEnhancementPrompt(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult, recommendations *IntelligentRecommendations) string {
	var prompt strings.Builder
	
	prompt.WriteString("作为网络安全专家，请分析以下安全查询结果并提供增强的推荐建议：\n\n")
	prompt.WriteString(fmt.Sprintf("查询: %s\n", query.Query))
	prompt.WriteString(fmt.Sprintf("意图: %s\n", query.Intent))
	prompt.WriteString(fmt.Sprintf("数据源数量: %d\n", len(results.Sources)))
	prompt.WriteString(fmt.Sprintf("执行成功率: %.1f%%\n", results.SuccessRate*100))
	
	if correlatedData != nil {
		prompt.WriteString(fmt.Sprintf("检测到威胁模式: %d 个\n", len(correlatedData.Patterns)))
		prompt.WriteString(fmt.Sprintf("数据关联: %d 个\n", len(correlatedData.Correlations)))
	}
	
	prompt.WriteString(fmt.Sprintf("当前推荐数量: 紧急 %d, 短期 %d, 长期 %d\n\n", 
		len(recommendations.Immediate), len(recommendations.ShortTerm), len(recommendations.LongTerm)))
	
	prompt.WriteString("请提供额外的专业建议和优化推荐。")
	
	return prompt.String()
}

func (re *RecommendationEngine) parseAndEnhanceRecommendations(aiResponse string, recommendations *IntelligentRecommendations) error {
	// 简化的AI响应解析
	// 实际项目中可以使用更复杂的NLP解析
	
	if strings.Contains(strings.ToLower(aiResponse), "urgent") || strings.Contains(strings.ToLower(aiResponse), "critical") {
		enhancement := Recommendation{
			ID:          "ai_urgent_recommendation",
			Type:        "ai_insight",
			Title:       "AI紧急建议",
			Description: "基于AI分析的紧急安全建议",
			Priority:    "high",
			Impact:      "high",
			Confidence:  0.7,
			Timestamp:   time.Now(),
			Context: map[string]interface{}{
				"ai_response": aiResponse,
			},
		}
		recommendations.Immediate = append(recommendations.Immediate, enhancement)
	}
	
	return nil
}

// initializeBuiltinRules 初始化内置规则
func (re *RecommendationEngine) initializeBuiltinRules() {
	// 低成功率规则
	re.rules = append(re.rules, &RecommendationRule{
		ID:   "low_success_rate",
		Name: "Low Success Rate Rule",
		ShouldApply: func(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult) bool {
			return results.SuccessRate < 0.7
		},
		GenerateRecommendation: func(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult) *Recommendation {
			return &Recommendation{
				ID:          "improve_success_rate",
				Type:        "system_improvement",
				Title:       "提升查询成功率",
				Description: "当前查询成功率较低，建议检查系统状态",
				Priority:    "medium",
				Impact:      "medium",
				Confidence:  0.8,
				Timestamp:   time.Now(),
			}
		},
	})

	// 高威胁检测规则
	re.rules = append(re.rules, &RecommendationRule{
		ID:   "high_threat_detection",
		Name: "High Threat Detection Rule",
		ShouldApply: func(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult) bool {
			if correlatedData == nil {
				return false
			}
			for _, pattern := range correlatedData.Patterns {
				if pattern.Severity == "high" || pattern.Severity == "critical" {
					return true
				}
			}
			return false
		},
		GenerateRecommendation: func(query *OrchestratedQuery, results *EnhancedResults, correlatedData *CorrelationResult) *Recommendation {
			return &Recommendation{
				ID:          "immediate_threat_response",
				Type:        "threat_response",
				Title:       "立即威胁响应",
				Description: "检测到高危威胁，需要立即采取响应措施",
				Priority:    "critical",
				Impact:      "high",
				Confidence:  0.9,
				Timestamp:   time.Now(),
			}
		},
	})
}

// RecommendationRule 推荐规则
type RecommendationRule struct {
	ID                     string
	Name                   string
	ShouldApply            func(*OrchestratedQuery, *EnhancedResults, *CorrelationResult) bool
	GenerateRecommendation func(*OrchestratedQuery, *EnhancedResults, *CorrelationResult) *Recommendation
}