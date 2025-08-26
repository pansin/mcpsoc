package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mcpsoc/mcpsoc/internal/detection"
	"github.com/sirupsen/logrus"
)

// AlertingSystem 告警系统
type AlertingSystem struct {
	logger      *logrus.Logger
	channels    map[string]NotificationChannel
	rules       map[string]*AlertingRule
	mu          sync.RWMutex
	enabled     bool
	metrics     *AlertingMetrics
}

// NewAlertingSystem 创建告警系统
func NewAlertingSystem(logger *logrus.Logger) *AlertingSystem {
	return &AlertingSystem{
		logger:   logger,
		channels: make(map[string]NotificationChannel),
		rules:    make(map[string]*AlertingRule),
		enabled:  true,
		metrics:  NewAlertingMetrics(),
	}
}

// NotificationChannel 通知渠道接口
type NotificationChannel interface {
	Send(ctx context.Context, notification *Notification) error
	GetType() string
	IsEnabled() bool
}

// AlertingRule 告警规则
type AlertingRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Conditions  []RuleCondition `json:"conditions"`
	Channels    []string        `json:"channels"`
	Throttle    time.Duration   `json:"throttle"`
	Template    string          `json:"template"`
	LastFired   time.Time       `json:"last_fired"`
}

// RuleCondition 规则条件
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// Notification 通知消息
type Notification struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    string                 `json:"priority"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Recipients  []string               `json:"recipients"`
}

// ProcessAlert 处理告警
func (as *AlertingSystem) ProcessAlert(ctx context.Context, alert *detection.ThreatAlert) error {
	if !as.enabled {
		return nil
	}

	as.logger.WithFields(logrus.Fields{
		"alert_id": alert.ID,
		"severity": alert.Severity,
		"rule_id":  alert.RuleID,
	}).Info("Processing alert for notifications")

	// 检查所有告警规则
	notifications := as.evaluateRules(alert)

	// 发送通知
	for _, notification := range notifications {
		if err := as.sendNotification(ctx, notification); err != nil {
			as.logger.WithError(err).WithField("notification_id", notification.ID).Error("Failed to send notification")
			as.metrics.IncrementFailedNotifications()
		} else {
			as.metrics.IncrementSentNotifications()
		}
	}

	return nil
}

// evaluateRules 评估告警规则
func (as *AlertingSystem) evaluateRules(alert *detection.ThreatAlert) []*Notification {
	as.mu.RLock()
	defer as.mu.RUnlock()

	var notifications []*Notification

	for _, rule := range as.rules {
		if !rule.Enabled {
			continue
		}

		// 检查节流
		if time.Since(rule.LastFired) < rule.Throttle {
			continue
		}

		// 评估条件
		if as.evaluateRuleConditions(rule, alert) {
			notification := as.createNotification(rule, alert)
			notifications = append(notifications, notification)
			
			// 更新最后触发时间
			rule.LastFired = time.Now()
		}
	}

	return notifications
}

// evaluateRuleConditions 评估规则条件
func (as *AlertingSystem) evaluateRuleConditions(rule *AlertingRule, alert *detection.ThreatAlert) bool {
	alertData := map[string]interface{}{
		"severity":    alert.Severity,
		"category":    alert.Category,
		"rule_id":     alert.RuleID,
		"rule_name":   alert.RuleName,
		"status":      alert.Status,
		"timestamp":   alert.Timestamp,
		"indicators":  alert.Indicators,
	}

	for _, condition := range rule.Conditions {
		if !as.evaluateCondition(condition, alertData) {
			return false
		}
	}

	return len(rule.Conditions) > 0
}

// evaluateCondition 评估单个条件
func (as *AlertingSystem) evaluateCondition(condition RuleCondition, data map[string]interface{}) bool {
	fieldValue, exists := data[condition.Field]
	if !exists {
		return false
	}

	switch condition.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", condition.Value)
	case "contains":
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", fieldValue)), 
			strings.ToLower(fmt.Sprintf("%v", condition.Value)))
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			fieldStr := fmt.Sprintf("%v", fieldValue)
			for _, val := range values {
				if fieldStr == fmt.Sprintf("%v", val) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// createNotification 创建通知
func (as *AlertingSystem) createNotification(rule *AlertingRule, alert *detection.ThreatAlert) *Notification {
	notification := &Notification{
		ID:        fmt.Sprintf("notif_%d", time.Now().UnixNano()),
		Type:      "security_alert",
		Priority:  as.mapSeverityToPriority(alert.Severity),
		Title:     fmt.Sprintf("安全告警: %s", alert.RuleName),
		Message:   as.renderTemplate(rule.Template, alert),
		Source:    "mcpsoc_alerting",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"alert_id":    alert.ID,
			"rule_id":     alert.RuleID,
			"severity":    alert.Severity,
			"category":    alert.Category,
			"indicators":  alert.Indicators,
			"source_data": alert.SourceData,
		},
	}

	return notification
}

// renderTemplate 渲染模板
func (as *AlertingSystem) renderTemplate(template string, alert *detection.ThreatAlert) string {
	if template == "" {
		return fmt.Sprintf("检测到%s级别的安全威胁：%s", alert.Severity, alert.Description)
	}

	// 简单的模板渲染
	message := template
	message = strings.ReplaceAll(message, "{{.RuleName}}", alert.RuleName)
	message = strings.ReplaceAll(message, "{{.Severity}}", alert.Severity)
	message = strings.ReplaceAll(message, "{{.Category}}", alert.Category)
	message = strings.ReplaceAll(message, "{{.Description}}", alert.Description)
	message = strings.ReplaceAll(message, "{{.Timestamp}}", alert.Timestamp.Format(time.RFC3339))

	return message
}

// sendNotification 发送通知
func (as *AlertingSystem) sendNotification(ctx context.Context, notification *Notification) error {
	as.mu.RLock()
	defer as.mu.RUnlock()

	// 记录通知
	as.logger.WithFields(logrus.Fields{
		"notification_id": notification.ID,
		"type":           notification.Type,
		"priority":       notification.Priority,
		"title":          notification.Title,
	}).Info("Sending notification")

	// 发送到所有配置的渠道
	var errors []error
	for channelID, channel := range as.channels {
		if !channel.IsEnabled() {
			continue
		}

		if err := channel.Send(ctx, notification); err != nil {
			errors = append(errors, fmt.Errorf("channel %s failed: %w", channelID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification failed on %d channels: %v", len(errors), errors)
	}

	return nil
}

// 通知渠道管理
func (as *AlertingSystem) RegisterChannel(id string, channel NotificationChannel) {
	as.mu.Lock()
	defer as.mu.Unlock()
	
	as.channels[id] = channel
	as.logger.WithFields(logrus.Fields{
		"channel_id":   id,
		"channel_type": channel.GetType(),
	}).Info("Notification channel registered")
}

func (as *AlertingSystem) UnregisterChannel(id string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	
	delete(as.channels, id)
	as.logger.WithField("channel_id", id).Info("Notification channel unregistered")
}

// 规则管理
func (as *AlertingSystem) AddRule(rule *AlertingRule) {
	as.mu.Lock()
	defer as.mu.Unlock()
	
	as.rules[rule.ID] = rule
	as.logger.WithField("rule_id", rule.ID).Info("Alerting rule added")
}

func (as *AlertingSystem) RemoveRule(ruleID string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	
	delete(as.rules, ruleID)
	as.logger.WithField("rule_id", ruleID).Info("Alerting rule removed")
}

func (as *AlertingSystem) GetRule(ruleID string) (*AlertingRule, bool) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	
	rule, exists := as.rules[ruleID]
	return rule, exists
}

func (as *AlertingSystem) ListRules() []*AlertingRule {
	as.mu.RLock()
	defer as.mu.RUnlock()
	
	var rules []*AlertingRule
	for _, rule := range as.rules {
		rules = append(rules, rule)
	}
	return rules
}

// 系统控制
func (as *AlertingSystem) Enable() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.enabled = true
	as.logger.Info("Alerting system enabled")
}

func (as *AlertingSystem) Disable() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.enabled = false
	as.logger.Info("Alerting system disabled")
}

func (as *AlertingSystem) GetMetrics() *AlertingMetrics {
	return as.metrics
}

// 辅助方法
func (as *AlertingSystem) mapSeverityToPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "urgent"
	case "high":
		return "high"
	case "medium":
		return "normal"
	case "low":
		return "low"
	default:
		return "normal"
	}
}

// 内置通知渠道实现

// EmailChannel 邮件通知渠道
type EmailChannel struct {
	enabled   bool
	smtpHost  string
	smtpPort  int
	username  string
	password  string
	fromEmail string
	toEmails  []string
}

func NewEmailChannel(smtpHost string, smtpPort int, username, password, fromEmail string, toEmails []string) *EmailChannel {
	return &EmailChannel{
		enabled:   true,
		smtpHost:  smtpHost,
		smtpPort:  smtpPort,
		username:  username,
		password:  password,
		fromEmail: fromEmail,
		toEmails:  toEmails,
	}
}

func (ec *EmailChannel) Send(ctx context.Context, notification *Notification) error {
	// 简化的邮件发送实现
	// 实际项目中需要使用SMTP库
	return fmt.Errorf("email sending not implemented")
}

func (ec *EmailChannel) GetType() string {
	return "email"
}

func (ec *EmailChannel) IsEnabled() bool {
	return ec.enabled
}

// SlackChannel Slack通知渠道
type SlackChannel struct {
	enabled    bool
	webhookURL string
	channel    string
	username   string
}

func NewSlackChannel(webhookURL, channel, username string) *SlackChannel {
	return &SlackChannel{
		enabled:    true,
		webhookURL: webhookURL,
		channel:    channel,
		username:   username,
	}
}

func (sc *SlackChannel) Send(ctx context.Context, notification *Notification) error {
	if sc.webhookURL == "" {
		return fmt.Errorf("slack webhook URL not configured")
	}

	// 构建Slack消息
	slackMsg := map[string]interface{}{
		"channel":  sc.channel,
		"username": sc.username,
		"text":     notification.Title,
		"attachments": []map[string]interface{}{
			{
				"color":    sc.getPriorityColor(notification.Priority),
				"title":    notification.Title,
				"text":     notification.Message,
				"footer":   "MCPSoc Security Platform",
				"ts":       notification.Timestamp.Unix(),
			},
		},
	}

	jsonData, err := json.Marshal(slackMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	// 发送HTTP请求
	req, err := http.NewRequestWithContext(ctx, "POST", sc.webhookURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (sc *SlackChannel) GetType() string {
	return "slack"
}

func (sc *SlackChannel) IsEnabled() bool {
	return sc.enabled
}

func (sc *SlackChannel) getPriorityColor(priority string) string {
	switch strings.ToLower(priority) {
	case "urgent":
		return "danger"
	case "high":
		return "warning"
	case "normal":
		return "good"
	case "low":
		return "#439FE0"
	default:
		return "good"
	}
}

// WebhookChannel 通用Webhook通知渠道
type WebhookChannel struct {
	enabled bool
	url     string
	headers map[string]string
	timeout time.Duration
}

func NewWebhookChannel(url string, headers map[string]string) *WebhookChannel {
	return &WebhookChannel{
		enabled: true,
		url:     url,
		headers: headers,
		timeout: 10 * time.Second,
	}
}

func (wc *WebhookChannel) Send(ctx context.Context, notification *Notification) error {
	jsonData, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", wc.url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range wc.headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: wc.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (wc *WebhookChannel) GetType() string {
	return "webhook"
}

func (wc *WebhookChannel) IsEnabled() bool {
	return wc.enabled
}

// AlertingMetrics 告警指标
type AlertingMetrics struct {
	mu                    sync.RWMutex
	totalNotifications    int64
	sentNotifications     int64
	failedNotifications   int64
	notificationsByType   map[string]int64
	notificationsByPriority map[string]int64
	lastNotificationTime  time.Time
}

func NewAlertingMetrics() *AlertingMetrics {
	return &AlertingMetrics{
		notificationsByType:     make(map[string]int64),
		notificationsByPriority: make(map[string]int64),
	}
}

func (am *AlertingMetrics) IncrementSentNotifications() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.totalNotifications++
	am.sentNotifications++
	am.lastNotificationTime = time.Now()
}

func (am *AlertingMetrics) IncrementFailedNotifications() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.totalNotifications++
	am.failedNotifications++
}

func (am *AlertingMetrics) GetStats() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return map[string]interface{}{
		"total_notifications":       am.totalNotifications,
		"sent_notifications":        am.sentNotifications,
		"failed_notifications":      am.failedNotifications,
		"notifications_by_type":     am.notificationsByType,
		"notifications_by_priority": am.notificationsByPriority,
		"last_notification_time":    am.lastNotificationTime,
	}
}