package ai

import (
	"fmt"
	"strings"
	"text/template"
	"bytes"
)

// PromptTemplate 提示词模板
type PromptTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Language    string            `json:"language"`
	Template    string            `json:"template"`
	Variables   []TemplateVar     `json:"variables"`
	Metadata    map[string]string `json:"metadata"`
}

// TemplateVar 模板变量
type TemplateVar struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default"`
}

// PromptManager 提示词管理器
type PromptManager struct {
	templates map[string]*PromptTemplate
}

// NewPromptManager 创建新的提示词管理器
func NewPromptManager() *PromptManager {
	manager := &PromptManager{
		templates: make(map[string]*PromptTemplate),
	}
	
	// 初始化默认模板
	manager.initDefaultTemplates()
	
	return manager
}

// RegisterTemplate 注册提示词模板
func (pm *PromptManager) RegisterTemplate(tmpl *PromptTemplate) error {
	if tmpl.ID == "" {
		return fmt.Errorf("template ID cannot be empty")
	}
	
	pm.templates[tmpl.ID] = tmpl
	return nil
}

// GetTemplate 获取提示词模板
func (pm *PromptManager) GetTemplate(id string) (*PromptTemplate, error) {
	tmpl, exists := pm.templates[id]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	
	return tmpl, nil
}

// RenderPrompt 渲染提示词
func (pm *PromptManager) RenderPrompt(templateID string, data map[string]interface{}) (string, error) {
	tmpl, err := pm.GetTemplate(templateID)
	if err != nil {
		return "", err
	}
	
	// 创建Go模板
	t, err := template.New(tmpl.ID).Parse(tmpl.Template)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	
	// 渲染模板
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	
	return buf.String(), nil
}

// ListTemplates 列出所有模板
func (pm *PromptManager) ListTemplates() []*PromptTemplate {
	templates := make([]*PromptTemplate, 0, len(pm.templates))
	for _, tmpl := range pm.templates {
		templates = append(templates, tmpl)
	}
	return templates
}

// GetTemplatesByCategory 按类别获取模板
func (pm *PromptManager) GetTemplatesByCategory(category string) []*PromptTemplate {
	var templates []*PromptTemplate
	for _, tmpl := range pm.templates {
		if tmpl.Category == category {
			templates = append(templates, tmpl)
		}
	}
	return templates
}

// initDefaultTemplates 初始化默认模板
func (pm *PromptManager) initDefaultTemplates() {
	// 威胁分析模板
	pm.RegisterTemplate(&PromptTemplate{
		ID:          "threat_analysis_basic",
		Name:        "基础威胁分析",
		Description: "分析安全事件并评估威胁级别",
		Category:    "threat_analysis",
		Language:    "zh-CN",
		Template: `你是一个专业的网络安全威胁分析专家。请分析以下安全数据并识别潜在威胁：

安全事件数据：
{{range $key, $value := .SecurityData}}
- {{$key}}: {{$value}}
{{end}}

请提供详细的威胁分析报告，包括：

1. **威胁级别评估**: 
   - 评估等级: low/medium/high/critical
   - 评估依据: 详细说明威胁级别的判断依据

2. **置信度评分**: 
   - 分数: 0.0-1.0
   - 评估理由: 说明置信度的计算依据

3. **威胁指标 (IOCs)**:
   - IP地址、域名、文件哈希等
   - 攻击技术和战术 (MITRE ATT&CK)

4. **影响评估**:
   - 潜在影响范围
   - 业务风险评估

5. **缓解措施**:
   - 即时响应建议
   - 长期防护措施

6. **推荐行动**:
   - 优先级排序的具体行动
   - 责任分配和时间线

请以结构化的方式提供分析结果。`,
		Variables: []TemplateVar{
			{Name: "SecurityData", Type: "map", Description: "安全事件数据", Required: true},
		},
	})

	// 事件响应模板
	pm.RegisterTemplate(&PromptTemplate{
		ID:          "incident_response_plan",
		Name:        "事件响应计划",
		Description: "生成详细的安全事件响应计划",
		Category:    "incident_response",
		Language:    "zh-CN",
		Template: `你是一个经验丰富的网络安全事件响应专家。请为以下安全事件生成详细的响应计划：

事件信息：
{{range $key, $value := .IncidentData}}
- {{$key}}: {{$value}}
{{end}}

请提供结构化的事件响应计划：

## 1. 事件摘要
- **事件ID**: {{.IncidentID}}
- **严重性等级**: 
- **影响范围**: 
- **检测时间**: 
- **报告时间**: 

## 2. 即时响应 (0-1小时)
### 2.1 遏制措施
- [ ] 隔离受影响系统
- [ ] 阻断恶意网络连接
- [ ] 停止可疑进程

### 2.2 证据保全
- [ ] 收集系统快照
- [ ] 保存日志文件
- [ ] 记录系统状态

## 3. 详细调查 (1-8小时)
### 3.1 攻击路径分析
- [ ] 确定初始入侵点
- [ ] 追踪横向移动
- [ ] 识别数据泄露

### 3.2 影响评估
- [ ] 确定受影响资产
- [ ] 评估数据损失
- [ ] 分析业务影响

## 4. 清除和恢复 (8-24小时)
### 4.1 威胁清除
- [ ] 删除恶意文件
- [ ] 修复系统漏洞
- [ ] 更新安全配置

### 4.2 系统恢复
- [ ] 恢复业务服务
- [ ] 验证系统完整性
- [ ] 加强监控

## 5. 事后活动 (1-7天)
### 5.1 事件报告
- [ ] 编写详细报告
- [ ] 通知相关方
- [ ] 合规性报告

### 5.2 改进措施
- [ ] 经验教训总结
- [ ] 防护能力提升
- [ ] 流程优化

## 6. 责任分配
- **事件指挥官**: {{.IncidentCommander | default "SOC经理"}}
- **技术负责人**: {{.TechnicalLead | default "安全工程师"}}
- **沟通负责人**: {{.CommunicationLead | default "安全主管"}}

## 7. 联系信息
- **紧急联系电话**: 
- **管理层通知**: 
- **外部支持**: `,
		Variables: []TemplateVar{
			{Name: "IncidentData", Type: "map", Description: "事件数据", Required: true},
			{Name: "IncidentID", Type: "string", Description: "事件ID", Required: false},
			{Name: "IncidentCommander", Type: "string", Description: "事件指挥官", Required: false},
			{Name: "TechnicalLead", Type: "string", Description: "技术负责人", Required: false},
			{Name: "CommunicationLead", Type: "string", Description: "沟通负责人", Required: false},
		},
	})

	// 自然语言查询转换模板
	pm.RegisterTemplate(&PromptTemplate{
		ID:          "nl_to_mcp_query",
		Name:        "自然语言到MCP查询转换",
		Description: "将自然语言查询转换为MCP工具调用",
		Category:    "query_translation",
		Language:    "zh-CN",
		Template: `你是一个专业的安全运营中心(SOC)查询转换器。你的任务是将用户的自然语言查询转换为具体的MCP工具调用。

用户查询: "{{.UserQuery}}"

可用的MCP工具:
{{range .AvailableTools}}
- **{{.Name}}**: {{.Description}}
  输入参数: {{range .Parameters}}{{.Name}}({{.Type}}) {{end}}
{{end}}

请分析用户查询的意图，并生成相应的MCP工具调用序列。

输出格式要求(JSON):
{
  "intent": "查询意图分类",
  "confidence": 0.0-1.0,
  "tool_calls": [
    {
      "tool": "工具名称",
      "arguments": {
        "参数名": "参数值"
      },
      "reason": "调用理由"
    }
  ],
  "execution_plan": {
    "parallel": ["可并行执行的工具"],
    "sequential": [["需顺序执行的工具组"]]
  },
  "expected_result": "预期结果描述"
}

请确保生成的工具调用是合理的、可执行的，并能回答用户的查询。`,
		Variables: []TemplateVar{
			{Name: "UserQuery", Type: "string", Description: "用户查询", Required: true},
			{Name: "AvailableTools", Type: "array", Description: "可用工具列表", Required: true},
		},
	})

	// 日志分析模板
	pm.RegisterTemplate(&PromptTemplate{
		ID:          "log_analysis",
		Name:        "安全日志分析",
		Description: "分析安全日志并识别异常",
		Category:    "log_analysis",
		Language:    "zh-CN",
		Template: `你是一个专业的安全日志分析专家。请分析以下日志数据并识别潜在的安全威胁：

日志数据:
{{.LogData}}

分析要求:
1. **时间线分析**: 按时间顺序梳理事件
2. **异常检测**: 识别不正常的活动模式
3. **关联分析**: 查找相关事件之间的联系
4. **威胁识别**: 判断是否存在安全威胁
5. **影响评估**: 评估潜在的安全影响

请提供详细的分析报告，包括:
- 发现的异常活动
- 可疑的IP地址、用户或进程
- 攻击技术和方法
- 建议的后续行动

分析结果请以结构化格式提供。`,
		Variables: []TemplateVar{
			{Name: "LogData", Type: "string", Description: "日志数据", Required: true},
		},
	})

	// 漏洞评估模板
	pm.RegisterTemplate(&PromptTemplate{
		ID:          "vulnerability_assessment",
		Name:        "漏洞评估",
		Description: "评估安全漏洞的风险和影响",
		Category:    "vulnerability_assessment",
		Language:    "zh-CN",
		Template: `你是一个专业的漏洞评估专家。请对以下漏洞进行详细的风险评估：

漏洞信息:
{{range $key, $value := .VulnerabilityData}}
- {{$key}}: {{$value}}
{{end}}

请提供完整的漏洞评估报告：

## 1. 漏洞概述
- **CVE编号**: {{.CVE}}
- **CVSS评分**: 
- **严重性等级**: 
- **影响组件**: 

## 2. 技术分析
- **漏洞类型**: 
- **攻击向量**: 
- **利用条件**: 
- **攻击复杂度**: 

## 3. 风险评估
- **可利用性**: 
- **影响程度**: 
- **业务风险**: 
- **紧急程度**: 

## 4. 修复建议
- **立即措施**: 
- **长期解决方案**: 
- **缓解控制**: 
- **监控要求**: 

## 5. 验证方法
- **测试步骤**: 
- **验证标准**: 
- **监控指标**: 

请确保评估的准确性和可操作性。`,
		Variables: []TemplateVar{
			{Name: "VulnerabilityData", Type: "map", Description: "漏洞数据", Required: true},
			{Name: "CVE", Type: "string", Description: "CVE编号", Required: false},
		},
	})
}