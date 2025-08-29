package detection

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ThreatDetectionEngine 威胁检测引擎
type ThreatDetectionEngine struct {
	logger   *logrus.Logger
	rules    map[string]*DetectionRule
	mu       sync.RWMutex
	enabled  bool
	metrics  *DetectionMetrics
}

// NewThreatDetectionEngine 创建威胁检测引擎
func NewThreatDetectionEngine(logger *logrus.Logger) *ThreatDetectionEngine {
	engine := &ThreatDetectionEngine{
		logger:  logger,
		rules:   make(map[string]*DetectionRule),
		enabled: true,
		metrics: NewDetectionMetrics(),
	}
	
	// 加载默认规则
	engine.loadDefaultRules()
	
	return engine
}

// DetectionRule 检测规则
type DetectionRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Enabled     bool              `json:"enabled"`
	Conditions  []RuleCondition   `json:"conditions"`
	Actions     []RuleAction      `json:"actions"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RuleCondition 规则条件
type RuleCondition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	CaseSensitive bool    `json:"case_sensitive"`
}

// RuleAction 规则动作
type RuleAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ThreatAlert 威胁告警
type ThreatAlert struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	SourceData  map[string]interface{} `json:"source_data"`
	Indicators  []string               `json:"indicators"`
	Actions     []string               `json:"actions"`
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"`
}

// DetectThreats 检测威胁
func (tde *ThreatDetectionEngine) DetectThreats(ctx context.Context, data map[string]interface{}) ([]*ThreatAlert, error) {
	if !tde.enabled {
		return nil, nil
	}

	tde.mu.RLock()
	defer tde.mu.RUnlock()

	var alerts []*ThreatAlert
	
	for _, rule := range tde.rules {
		if !rule.Enabled {
			continue
		}

		if tde.evaluateRule(rule, data) {
			alert := tde.createAlert(rule, data)
			alerts = append(alerts, alert)
			
			tde.metrics.IncrementRuleMatch(rule.ID)
			tde.executeRuleActions(rule, alert)
		}
	}

	if len(alerts) > 0 {
		tde.metrics.IncrementDetectionCount(len(alerts))
	}

	return alerts, nil
}

// evaluateRule 评估规则
func (tde *ThreatDetectionEngine) evaluateRule(rule *DetectionRule, data map[string]interface{}) bool {
	for _, condition := range rule.Conditions {
		if !tde.evaluateCondition(condition, data) {
			return false // 所有条件必须满足
		}
	}
	return len(rule.Conditions) > 0
}

// evaluateCondition 评估条件
func (tde *ThreatDetectionEngine) evaluateCondition(condition RuleCondition, data map[string]interface{}) bool {
	fieldValue, exists := data[condition.Field]
	if !exists {
		return false
	}

	switch condition.Operator {
	case "equals":
		return tde.compareEqual(fieldValue, condition.Value, condition.CaseSensitive)
	case "contains":
		return tde.compareContains(fieldValue, condition.Value, condition.CaseSensitive)
	case "regex":
		return tde.compareRegex(fieldValue, condition.Value)
	case "greater_than":
		return tde.compareGreater(fieldValue, condition.Value)
	case "less_than":
		return tde.compareLess(fieldValue, condition.Value)
	default:
		return false
	}
}

// 比较函数
func (tde *ThreatDetectionEngine) compareEqual(fieldValue, condValue interface{}, caseSensitive bool) bool {
	fieldStr := fmt.Sprintf("%v", fieldValue)
	condStr := fmt.Sprintf("%v", condValue)
	
	if !caseSensitive {
		fieldStr = strings.ToLower(fieldStr)
		condStr = strings.ToLower(condStr)
	}
	
	return fieldStr == condStr
}

func (tde *ThreatDetectionEngine) compareContains(fieldValue, condValue interface{}, caseSensitive bool) bool {
	fieldStr := fmt.Sprintf("%v", fieldValue)
	condStr := fmt.Sprintf("%v", condValue)
	
	if !caseSensitive {
		fieldStr = strings.ToLower(fieldStr)
		condStr = strings.ToLower(condStr)
	}
	
	return strings.Contains(fieldStr, condStr)
}

func (tde *ThreatDetectionEngine) compareRegex(fieldValue, condValue interface{}) bool {
	fieldStr := fmt.Sprintf("%v", fieldValue)
	pattern := fmt.Sprintf("%v", condValue)
	
	matched, err := regexp.MatchString(pattern, fieldStr)
	if err != nil {
		tde.logger.WithError(err).Warn("Regex evaluation failed")
		return false
	}
	
	return matched
}

func (tde *ThreatDetectionEngine) compareGreater(fieldValue, condValue interface{}) bool {
	// 简化的数值比较
	if fVal, ok := fieldValue.(float64); ok {
		if cVal, ok := condValue.(float64); ok {
			return fVal > cVal
		}
	}
	return false
}

func (tde *ThreatDetectionEngine) compareLess(fieldValue, condValue interface{}) bool {
	if fVal, ok := fieldValue.(float64); ok {
		if cVal, ok := condValue.(float64); ok {
			return fVal < cVal
		}
	}
	return false
}

// createAlert 创建告警
func (tde *ThreatDetectionEngine) createAlert(rule *DetectionRule, data map[string]interface{}) *ThreatAlert {
	return &ThreatAlert{
		ID:          fmt.Sprintf("alert_%d", time.Now().UnixNano()),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Category:    rule.Category,
		Title:       rule.Name,
		Description: rule.Description,
		SourceData:  data,
		Indicators:  tde.extractIndicators(rule, data),
		Actions:     tde.getActionTypes(rule.Actions),
		Timestamp:   time.Now(),
		Status:      "open",
	}
}

// loadDefaultRules 加载默认规则
func (tde *ThreatDetectionEngine) loadDefaultRules() {
	rules := []*DetectionRule{
		{
			ID:          "failed_login_attempts",
			Name:        "多次登录失败",
			Description: "检测到多次登录失败尝试",
			Category:    "authentication",
			Severity:    "medium",
			Enabled:     true,
			Conditions: []RuleCondition{
				{Field: "event_type", Operator: "equals", Value: "login_failed"},
				{Field: "failure_count", Operator: "greater_than", Value: float64(5)},
			},
			Actions: []RuleAction{
				{Type: "alert", Parameters: map[string]interface{}{"notify": true}},
			},
			CreatedAt: time.Now(),
		},
		{
			ID:          "suspicious_ip_access",
			Name:        "可疑IP访问",
			Description: "检测到来自可疑IP的访问",
			Category:    "network",
			Severity:    "high",
			Enabled:     true,
			Conditions: []RuleCondition{
				{Field: "src_ip", Operator: "regex", Value: "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"},
			},
			Actions: []RuleAction{
				{Type: "block", Parameters: map[string]interface{}{"duration": 3600}},
			},
			CreatedAt: time.Now(),
		},
		{
			ID:          "malware_detected",
			Name:        "恶意软件检测",
			Description: "检测到恶意软件",
			Category:    "malware",
			Severity:    "critical",
			Enabled:     true,
			Conditions: []RuleCondition{
				{Field: "scan_result", Operator: "contains", Value: "FOUND", CaseSensitive: false},
			},
			Actions: []RuleAction{
				{Type: "quarantine", Parameters: map[string]interface{}{"immediate": true}},
				{Type: "alert", Parameters: map[string]interface{}{"priority": "high"}},
			},
			CreatedAt: time.Now(),
		},
	}

	for _, rule := range rules {
		tde.rules[rule.ID] = rule
	}

	tde.logger.WithField("rule_count", len(rules)).Info("Default detection rules loaded")
}

// 规则管理方法
func (tde *ThreatDetectionEngine) AddRule(rule *DetectionRule) error {
	tde.mu.Lock()
	defer tde.mu.Unlock()

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	tde.rules[rule.ID] = rule

	tde.logger.WithField("rule_id", rule.ID).Info("Detection rule added")
	return nil
}

func (tde *ThreatDetectionEngine) GetRule(ruleID string) (*DetectionRule, error) {
	tde.mu.RLock()
	defer tde.mu.RUnlock()

	rule, exists := tde.rules[ruleID]
	if !exists {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}

	return rule, nil
}

func (tde *ThreatDetectionEngine) ListRules() []*DetectionRule {
	tde.mu.RLock()
	defer tde.mu.RUnlock()

	var rules []*DetectionRule
	for _, rule := range tde.rules {
		rules = append(rules, rule)
	}

	return rules
}

func (tde *ThreatDetectionEngine) EnableRule(ruleID string) error {
	tde.mu.Lock()
	defer tde.mu.Unlock()

	rule, exists := tde.rules[ruleID]
	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	rule.Enabled = true
	rule.UpdatedAt = time.Now()
	return nil
}

func (tde *ThreatDetectionEngine) DisableRule(ruleID string) error {
	tde.mu.Lock()
	defer tde.mu.Unlock()

	rule, exists := tde.rules[ruleID]
	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	rule.Enabled = false
	rule.UpdatedAt = time.Now()
	return nil
}

// 引擎控制
func (tde *ThreatDetectionEngine) Enable() {
	tde.mu.Lock()
	defer tde.mu.Unlock()
	tde.enabled = true
	tde.logger.Info("Threat detection engine enabled")
}

func (tde *ThreatDetectionEngine) Disable() {
	tde.mu.Lock()
	defer tde.mu.Unlock()
	tde.enabled = false
	tde.logger.Info("Threat detection engine disabled")
}

func (tde *ThreatDetectionEngine) GetMetrics() *DetectionMetrics {
	return tde.metrics
}

// 辅助方法
func (tde *ThreatDetectionEngine) extractIndicators(rule *DetectionRule, data map[string]interface{}) []string {
	var indicators []string
	for _, condition := range rule.Conditions {
		if value, ok := data[condition.Field]; ok {
			indicators = append(indicators, fmt.Sprintf("%s:%v", condition.Field, value))
		}
	}
	return indicators
}

func (tde *ThreatDetectionEngine) getActionTypes(actions []RuleAction) []string {
	var actionTypes []string
	for _, action := range actions {
		actionTypes = append(actionTypes, action.Type)
	}
	return actionTypes
}

func (tde *ThreatDetectionEngine) executeRuleActions(rule *DetectionRule, alert *ThreatAlert) {
	for _, action := range rule.Actions {
		switch action.Type {
		case "alert":
			tde.logger.WithFields(logrus.Fields{
				"alert_id": alert.ID,
				"rule_id":  rule.ID,
				"severity": alert.Severity,
			}).Warn("Threat alert generated")
		case "block":
			tde.logger.WithField("alert_id", alert.ID).Info("Block action triggered")
		case "quarantine":
			tde.logger.WithField("alert_id", alert.ID).Info("Quarantine action triggered")
		}
	}
}

// DetectionMetrics 检测指标
type DetectionMetrics struct {
	mu                 sync.RWMutex
	totalDetections    int64
	ruleMatchCounts    map[string]int64
	severityCounts     map[string]int64
	categoryCounts     map[string]int64
	lastDetectionTime  time.Time
}

func NewDetectionMetrics() *DetectionMetrics {
	return &DetectionMetrics{
		ruleMatchCounts: make(map[string]int64),
		severityCounts:  make(map[string]int64),
		categoryCounts:  make(map[string]int64),
	}
}

func (dm *DetectionMetrics) IncrementDetectionCount(count int) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.totalDetections += int64(count)
	dm.lastDetectionTime = time.Now()
}

func (dm *DetectionMetrics) IncrementRuleMatch(ruleID string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.ruleMatchCounts[ruleID]++
}

func (dm *DetectionMetrics) GetStats() map[string]interface{} {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	return map[string]interface{}{
		"total_detections":    dm.totalDetections,
		"rule_match_counts":   dm.ruleMatchCounts,
		"severity_counts":     dm.severityCounts,
		"category_counts":     dm.categoryCounts,
		"last_detection_time": dm.lastDetectionTime,
	}
}