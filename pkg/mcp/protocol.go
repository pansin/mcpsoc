package mcp

import (
	"encoding/json"
	"fmt"
)

// MCP协议版本
const (
	ProtocolVersion = "2025-06-18"
)

// JSON-RPC 2.0 消息类型
type MessageType string

const (
	MessageTypeRequest      MessageType = "request"
	MessageTypeResponse     MessageType = "response"
	MessageTypeNotification MessageType = "notification"
)

// JSONRPCMessage JSON-RPC 2.0 基础消息结构
type JSONRPCMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError JSON-RPC 2.0 错误结构
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error 实现error接口
func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// MCP错误代码
const (
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
	ErrorCodeServerError    = -32000
)

// MCP核心能力类型
type CapabilityType string

const (
	CapabilityTools     CapabilityType = "tools"
	CapabilityResources CapabilityType = "resources"
	CapabilityPrompts   CapabilityType = "prompts"
)

// ServerCapabilities MCP服务器能力声明
type ServerCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Logging   *LoggingCapability   `json:"logging,omitempty"`
}

// ToolsCapability 工具能力
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability 资源能力
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability 提示能力
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// LoggingCapability 日志能力
type LoggingCapability struct{}

// Tool MCP工具定义
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema JSONSchema  `json:"inputSchema"`
}

// JSONSchema JSON Schema定义
type JSONSchema struct {
	Type        string                 `json:"type"`
	Properties  map[string]JSONSchema  `json:"properties,omitempty"`
	Required    []string               `json:"required,omitempty"`
	Items       *JSONSchema            `json:"items,omitempty"`
	Enum        []interface{}          `json:"enum,omitempty"`
	Description string                 `json:"description,omitempty"`
}

// Resource MCP资源定义
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// Prompt MCP提示定义
type Prompt struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Arguments   []PromptArgument  `json:"arguments,omitempty"`
}

// PromptArgument 提示参数
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// ToolResult 工具执行结果
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content 内容结构
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// ResourceContent 资源内容
type ResourceContent struct {
	Contents []Content `json:"contents"`
}

// MCP协议方法名
const (
	MethodInitialize       = "initialize"
	MethodInitialized      = "initialized"
	MethodPing             = "ping"
	MethodListTools        = "tools/list"
	MethodCallTool         = "tools/call"
	MethodListResources    = "resources/list"
	MethodReadResource     = "resources/read"
	MethodListPrompts      = "prompts/list"
	MethodGetPrompt        = "prompts/get"
	MethodSetLevel         = "logging/setLevel"
)

// InitializeRequest 初始化请求
type InitializeRequest struct {
	ProtocolVersion string              `json:"protocolVersion"`
	Capabilities    ClientCapabilities  `json:"capabilities"`
	ClientInfo      ClientInfo          `json:"clientInfo"`
}

// ClientCapabilities 客户端能力
type ClientCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Sampling     map[string]interface{} `json:"sampling,omitempty"`
}

// ClientInfo 客户端信息
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult 初始化响应
type InitializeResult struct {
	ProtocolVersion string              `json:"protocolVersion"`
	Capabilities    ServerCapabilities  `json:"capabilities"`
	ServerInfo      ServerInfo          `json:"serverInfo"`
}

// ServerInfo 服务器信息
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ListToolsResult 工具列表响应
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolRequest 工具调用请求
type CallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ListResourcesResult 资源列表响应
type ListResourcesResult struct {
	Resources []Resource `json:"resources"`
}

// ReadResourceRequest 读取资源请求
type ReadResourceRequest struct {
	URI string `json:"uri"`
}

// ListPromptsResult 提示列表响应
type ListPromptsResult struct {
	Prompts []Prompt `json:"prompts"`
}

// GetPromptRequest 获取提示请求
type GetPromptRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// GetPromptResult 获取提示响应
type GetPromptResult struct {
	Description string    `json:"description,omitempty"`
	Messages    []Message `json:"messages"`
}

// Message 消息结构
type Message struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// NewRequest 创建新的请求消息
func NewRequest(id interface{}, method string, params interface{}) *JSONRPCMessage {
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
}

// NewResponse 创建新的响应消息
func NewResponse(id interface{}, result interface{}) *JSONRPCMessage {
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

// NewErrorResponse 创建新的错误响应消息
func NewErrorResponse(id interface{}, code int, message string, data interface{}) *JSONRPCMessage {
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// NewNotification 创建新的通知消息
func NewNotification(method string, params interface{}) *JSONRPCMessage {
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
}

// IsRequest 检查是否为请求消息
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && m.ID != nil
}

// IsResponse 检查是否为响应消息
func (m *JSONRPCMessage) IsResponse() bool {
	return m.Method == "" && m.ID != nil
}

// IsNotification 检查是否为通知消息
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && m.ID == nil
}

// IsError 检查是否为错误响应
func (m *JSONRPCMessage) IsError() bool {
	return m.Error != nil
}

// Marshal 序列化消息
func (m *JSONRPCMessage) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal 反序列化消息
func UnmarshalMessage(data []byte) (*JSONRPCMessage, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}