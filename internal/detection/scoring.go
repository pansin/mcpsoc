package detection

import (
	"math"
	"strings"
	"time"
)

// ThreatScoringEngine 威胁评分引擎
type ThreatScoringEngine struct {
	weights ScoringWeights
}

// ScoringWeights 评分权重配置
type ScoringWeights struct {
	SeverityWeight    float64 `json:"severity_weight"`
	ConfidenceWeight  float64 `json:"confidence_weight"`
	FrequencyWeight   float64 `json:"frequency_weight"`
	SourceWeight      float64 `json:"source_weight"`
	TimeDecayWeight   float64 `json:"time_decay_weight"`
	AssetValueWeight  float64 `json:"asset_value_weight"`
}

// ThreatScore 威胁评分结果
type ThreatScore struct {
	TotalScore      float64            `json:"total_score"`
	Priority        string             `json:"priority"`
	ComponentScores map[string]float64 `json:"component_scores"`
	Explanation     string             `json:"explanation"`
	Confidence      float64            `json:"confidence"`
}

// NewThreatScoringEngine 创建威胁评分引擎
func NewThreatScoringEngine() *ThreatScoringEngine {
	return &ThreatScoringEngine{
		weights: ScoringWeights{
			SeverityWeight:   0.3,  // 30%
			ConfidenceWeight: 0.25, // 25%
			FrequencyWeight:  0.2,  // 20%
			SourceWeight:     0.1,  // 10%
			TimeDecayWeight:  0.1,  // 10%
			AssetValueWeight: 0.05, // 5%
		},
	}
}

// CalculateScore 计算威胁评分
func (tse *ThreatScoringEngine) CalculateScore(alert *ThreatAlert, context *ScoringContext) *ThreatScore {
	componentScores := make(map[string]float64)
	
	// 1. 严重性评分 (0-100)
	severityScore := tse.calculateSeverityScore(alert.Severity)
	componentScores["severity"] = severityScore
	
	// 2. 置信度评分 (0-100)
	confidenceScore := tse.calculateConfidenceScore(context)
	componentScores["confidence"] = confidenceScore
	
	// 3. 频率评分 (0-100)
	frequencyScore := tse.calculateFrequencyScore(context)
	componentScores["frequency"] = frequencyScore
	
	// 4. 数据源评分 (0-100)
	sourceScore := tse.calculateSourceScore(context)
	componentScores["source"] = sourceScore
	
	// 5. 时间衰减评分 (0-100)
	timeDecayScore := tse.calculateTimeDecayScore(alert.Timestamp)
	componentScores["time_decay"] = timeDecayScore
	
	// 6. 资产价值评分 (0-100)
	assetValueScore := tse.calculateAssetValueScore(context)
	componentScores["asset_value"] = assetValueScore
	
	// 计算加权总分
	totalScore := severityScore*tse.weights.SeverityWeight +
		confidenceScore*tse.weights.ConfidenceWeight +
		frequencyScore*tse.weights.FrequencyWeight +
		sourceScore*tse.weights.SourceWeight +
		timeDecayScore*tse.weights.TimeDecayWeight +
		assetValueScore*tse.weights.AssetValueWeight
	
	// 确保分数在0-100范围内
	totalScore = math.Max(0, math.Min(100, totalScore))
	
	// 确定优先级
	priority := tse.determinePriority(totalScore)
	
	// 生成解释
	explanation := tse.generateExplanation(componentScores, totalScore)
	
	// 计算整体置信度
	confidence := tse.calculateOverallConfidence(componentScores)
	
	return &ThreatScore{
		TotalScore:      totalScore,
		Priority:        priority,
		ComponentScores: componentScores,
		Explanation:     explanation,
		Confidence:      confidence,
	}
}

// calculateSeverityScore 计算严重性评分
func (tse *ThreatScoringEngine) calculateSeverityScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 100.0
	case "high":
		return 80.0
	case "medium":
		return 60.0
	case "low":
		return 40.0
	case "info":
		return 20.0
	default:
		return 50.0
	}
}

// calculateConfidenceScore 计算置信度评分
func (tse *ThreatScoringEngine) calculateConfidenceScore(context *ScoringContext) float64 {
	if context == nil || context.DetectionConfidence == 0 {
		return 50.0 // 默认中等置信度
	}
	
	// 置信度通常是0-1之间的值，转换为0-100分
	return context.DetectionConfidence * 100
}

// calculateFrequencyScore 计算频率评分
func (tse *ThreatScoringEngine) calculateFrequencyScore(context *ScoringContext) float64 {
	if context == nil {
		return 20.0 // 默认低频
	}
	
	// 基于历史发生频率计算分数
	switch {
	case context.HistoricalFrequency >= 10: // 高频
		return 90.0
	case context.HistoricalFrequency >= 5: // 中高频
		return 70.0
	case context.HistoricalFrequency >= 2: // 中频
		return 50.0
	case context.HistoricalFrequency == 1: // 低频
		return 30.0
	default: // 首次发生
		return 20.0
	}
}

// calculateSourceScore 计算数据源评分
func (tse *ThreatScoringEngine) calculateSourceScore(context *ScoringContext) float64 {
	if context == nil || len(context.DataSources) == 0 {
		return 40.0 // 默认中低分
	}
	
	// 基于数据源数量和可信度
	baseScore := float64(len(context.DataSources)) * 15.0 // 每个数据源15分
	
	// 考虑数据源的可信度
	reliabilityBonus := 0.0
	for _, source := range context.DataSources {
		switch source.Reliability {
		case "high":
			reliabilityBonus += 10.0
		case "medium":
			reliabilityBonus += 5.0
		case "low":
			reliabilityBonus += 2.0
		}
	}
	
	totalScore := baseScore + reliabilityBonus
	return math.Min(100.0, totalScore)
}

// calculateTimeDecayScore 计算时间衰减评分
func (tse *ThreatScoringEngine) calculateTimeDecayScore(alertTime time.Time) float64 {
	// 计算距离现在的时间差
	timeDiff := time.Since(alertTime)
	
	// 时间衰减函数：新近的事件分数更高
	switch {
	case timeDiff < 5*time.Minute: // 5分钟内
		return 100.0
	case timeDiff < 30*time.Minute: // 30分钟内
		return 90.0
	case timeDiff < 2*time.Hour: // 2小时内
		return 80.0
	case timeDiff < 24*time.Hour: // 24小时内
		return 60.0
	case timeDiff < 7*24*time.Hour: // 7天内
		return 40.0
	default: // 超过7天
		return 20.0
	}
}

// calculateAssetValueScore 计算资产价值评分
func (tse *ThreatScoringEngine) calculateAssetValueScore(context *ScoringContext) float64 {
	if context == nil {
		return 50.0 // 默认中等价值
	}
	
	switch strings.ToLower(context.AssetCriticality) {
	case "critical":
		return 100.0
	case "high":
		return 80.0
	case "medium":
		return 60.0
	case "low":
		return 40.0
	default:
		return 50.0
	}
}

// determinePriority 确定优先级
func (tse *ThreatScoringEngine) determinePriority(score float64) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 75:
		return "high"
	case score >= 50:
		return "medium"
	case score >= 25:
		return "low"
	default:
		return "info"
	}
}

// generateExplanation 生成解释说明
func (tse *ThreatScoringEngine) generateExplanation(componentScores map[string]float64, totalScore float64) string {
	var explanations []string
	
	// 找出最高的几个评分组件
	if componentScores["severity"] >= 80 {
		explanations = append(explanations, "高严重性等级")
	}
	if componentScores["confidence"] >= 80 {
		explanations = append(explanations, "高检测置信度")
	}
	if componentScores["frequency"] >= 70 {
		explanations = append(explanations, "高发生频率")
	}
	if componentScores["time_decay"] >= 90 {
		explanations = append(explanations, "近期发生")
	}
	if componentScores["asset_value"] >= 80 {
		explanations = append(explanations, "高价值资产")
	}
	
	if len(explanations) == 0 {
		return "基于综合评估的威胁评分"
	}
	
	return "主要因素: " + strings.Join(explanations, ", ")
}

// calculateOverallConfidence 计算整体置信度
func (tse *ThreatScoringEngine) calculateOverallConfidence(componentScores map[string]float64) float64 {
	// 基于各组件分数的方差来计算置信度
	// 方差越小，置信度越高
	
	var scores []float64
	for _, score := range componentScores {
		scores = append(scores, score)
	}
	
	if len(scores) == 0 {
		return 0.5
	}
	
	// 计算平均值
	sum := 0.0
	for _, score := range scores {
		sum += score
	}
	mean := sum / float64(len(scores))
	
	// 计算方差
	variance := 0.0
	for _, score := range scores {
		variance += math.Pow(score-mean, 2)
	}
	variance = variance / float64(len(scores))
	
	// 将方差转换为置信度 (方差越小置信度越高)
	// 最大方差为2500 (当分数分布在0和100之间时)
	maxVariance := 2500.0
	confidence := 1.0 - (variance / maxVariance)
	
	return math.Max(0.0, math.Min(1.0, confidence))
}

// UpdateWeights 更新评分权重
func (tse *ThreatScoringEngine) UpdateWeights(weights ScoringWeights) {
	// 确保权重和为1
	total := weights.SeverityWeight + weights.ConfidenceWeight + 
		weights.FrequencyWeight + weights.SourceWeight + 
		weights.TimeDecayWeight + weights.AssetValueWeight
	
	if total > 0 {
		weights.SeverityWeight /= total
		weights.ConfidenceWeight /= total
		weights.FrequencyWeight /= total
		weights.SourceWeight /= total
		weights.TimeDecayWeight /= total
		weights.AssetValueWeight /= total
	}
	
	tse.weights = weights
}

// GetWeights 获取当前权重配置
func (tse *ThreatScoringEngine) GetWeights() ScoringWeights {
	return tse.weights
}

// ScoringContext 评分上下文
type ScoringContext struct {
	DetectionConfidence  float64        `json:"detection_confidence"`
	HistoricalFrequency  int            `json:"historical_frequency"`
	DataSources         []DataSource   `json:"data_sources"`
	AssetCriticality    string         `json:"asset_criticality"`
	NetworkContext      *NetworkContext `json:"network_context,omitempty"`
	UserContext         *UserContext    `json:"user_context,omitempty"`
}

// DataSource 数据源信息
type DataSource struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Reliability string `json:"reliability"`
}

// NetworkContext 网络上下文
type NetworkContext struct {
	InternalIP    bool   `json:"internal_ip"`
	GeoLocation   string `json:"geo_location"`
	ISP          string `json:"isp"`
	ThreatIntel   bool   `json:"threat_intel_match"`
}

// UserContext 用户上下文
type UserContext struct {
	Privileged    bool   `json:"privileged"`
	Department    string `json:"department"`
	RiskLevel     string `json:"risk_level"`
	RecentChanges bool   `json:"recent_changes"`
}