package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// Server MCP服务器接口
type Server interface {
	// 获取服务器信息
	GetServerInfo() ServerInfo
	
	// 获取服务器能力
	GetCapabilities() ServerCapabilities
	
	// 处理初始化请求
	HandleInitialize(ctx context.Context, req *InitializeRequest) (*InitializeResult, error)
	
	// 列出工具
	ListTools(ctx context.Context) (*ListToolsResult, error)
	
	// 调用工具
	CallTool(ctx context.Context, req *CallToolRequest) (*ToolResult, error)
	
	// 列出资源
	ListResources(ctx context.Context) (*ListResourcesResult, error)
	
	// 读取资源
	ReadResource(ctx context.Context, req *ReadResourceRequest) (*ResourceContent, error)
	
	// 列出提示
	ListPrompts(ctx context.Context) (*ListPromptsResult, error)
	
	// 获取提示
	GetPrompt(ctx context.Context, req *GetPromptRequest) (*GetPromptResult, error)
}

// BaseServer MCP服务器基础实现
type BaseServer struct {
	serverInfo   ServerInfo
	capabilities ServerCapabilities
	tools        map[string]Tool
	resources    map[string]Resource
	prompts      map[string]Prompt
	toolHandlers map[string]ToolHandler
}

// ToolHandler 工具处理器函数类型
type ToolHandler func(ctx context.Context, args map[string]interface{}) (*ToolResult, error)

// NewBaseServer 创建基础服务器
func NewBaseServer(name, version string) *BaseServer {
	return &BaseServer{
		serverInfo: ServerInfo{
			Name:    name,
			Version: version,
		},
		capabilities: ServerCapabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
			Resources: &ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
			Prompts: &PromptsCapability{
				ListChanged: false,
			},
		},
		tools:        make(map[string]Tool),
		resources:    make(map[string]Resource),
		prompts:      make(map[string]Prompt),
		toolHandlers: make(map[string]ToolHandler),
	}
}

// GetServerInfo 获取服务器信息
func (s *BaseServer) GetServerInfo() ServerInfo {
	return s.serverInfo
}

// GetCapabilities 获取服务器能力
func (s *BaseServer) GetCapabilities() ServerCapabilities {
	return s.capabilities
}

// RegisterTool 注册工具
func (s *BaseServer) RegisterTool(tool Tool, handler ToolHandler) {
	s.tools[tool.Name] = tool
	s.toolHandlers[tool.Name] = handler
}

// RegisterResource 注册资源
func (s *BaseServer) RegisterResource(resource Resource) {
	s.resources[resource.URI] = resource
}

// RegisterPrompt 注册提示
func (s *BaseServer) RegisterPrompt(prompt Prompt) {
	s.prompts[prompt.Name] = prompt
}

// HandleInitialize 处理初始化请求
func (s *BaseServer) HandleInitialize(ctx context.Context, req *InitializeRequest) (*InitializeResult, error) {
	return &InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    s.capabilities,
		ServerInfo:      s.serverInfo,
	}, nil
}

// ListTools 列出工具
func (s *BaseServer) ListTools(ctx context.Context) (*ListToolsResult, error) {
	tools := make([]Tool, 0, len(s.tools))
	for _, tool := range s.tools {
		tools = append(tools, tool)
	}
	
	return &ListToolsResult{
		Tools: tools,
	}, nil
}

// CallTool 调用工具
func (s *BaseServer) CallTool(ctx context.Context, req *CallToolRequest) (*ToolResult, error) {
	handler, exists := s.toolHandlers[req.Name]
	if !exists {
		return nil, fmt.Errorf("tool not found: %s", req.Name)
	}
	
	return handler(ctx, req.Arguments)
}

// ListResources 列出资源
func (s *BaseServer) ListResources(ctx context.Context) (*ListResourcesResult, error) {
	resources := make([]Resource, 0, len(s.resources))
	for _, resource := range s.resources {
		resources = append(resources, resource)
	}
	
	return &ListResourcesResult{
		Resources: resources,
	}, nil
}

// ReadResource 读取资源
func (s *BaseServer) ReadResource(ctx context.Context, req *ReadResourceRequest) (*ResourceContent, error) {
	_, exists := s.resources[req.URI]
	if !exists {
		return nil, fmt.Errorf("resource not found: %s", req.URI)
	}
	
	// 这里应该实现具体的资源读取逻辑
	// 基础实现返回空内容
	return &ResourceContent{
		Contents: []Content{},
	}, nil
}

// ListPrompts 列出提示
func (s *BaseServer) ListPrompts(ctx context.Context) (*ListPromptsResult, error) {
	prompts := make([]Prompt, 0, len(s.prompts))
	for _, prompt := range s.prompts {
		prompts = append(prompts, prompt)
	}
	
	return &ListPromptsResult{
		Prompts: prompts,
	}, nil
}

// GetPrompt 获取提示
func (s *BaseServer) GetPrompt(ctx context.Context, req *GetPromptRequest) (*GetPromptResult, error) {
	prompt, exists := s.prompts[req.Name]
	if !exists {
		return nil, fmt.Errorf("prompt not found: %s", req.Name)
	}
	
	// 这里应该实现具体的提示生成逻辑
	// 基础实现返回空消息
	return &GetPromptResult{
		Description: prompt.Description,
		Messages:    []Message{},
	}, nil
}

// RequestHandler MCP请求处理器
type RequestHandler struct {
	server Server
}

// NewRequestHandler 创建请求处理器
func NewRequestHandler(server Server) *RequestHandler {
	return &RequestHandler{
		server: server,
	}
}

// HandleRequest 处理MCP请求
func (h *RequestHandler) HandleRequest(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	switch msg.Method {
	case MethodInitialize:
		return h.handleInitialize(ctx, msg)
	case MethodListTools:
		return h.handleListTools(ctx, msg)
	case MethodCallTool:
		return h.handleCallTool(ctx, msg)
	case MethodListResources:
		return h.handleListResources(ctx, msg)
	case MethodReadResource:
		return h.handleReadResource(ctx, msg)
	case MethodListPrompts:
		return h.handleListPrompts(ctx, msg)
	case MethodGetPrompt:
		return h.handleGetPrompt(ctx, msg)
	case MethodPing:
		return h.handlePing(ctx, msg)
	default:
		return NewErrorResponse(msg.ID, ErrorCodeMethodNotFound, "Method not found", nil)
	}
}

func (h *RequestHandler) handleInitialize(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	var req InitializeRequest
	if err := h.unmarshalParams(msg.Params, &req); err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInvalidParams, "Invalid parameters", nil)
	}
	
	result, err := h.server.HandleInitialize(ctx, &req)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handleListTools(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	result, err := h.server.ListTools(ctx)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handleCallTool(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	var req CallToolRequest
	if err := h.unmarshalParams(msg.Params, &req); err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInvalidParams, "Invalid parameters", nil)
	}
	
	result, err := h.server.CallTool(ctx, &req)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handleListResources(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	result, err := h.server.ListResources(ctx)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handleReadResource(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	var req ReadResourceRequest
	if err := h.unmarshalParams(msg.Params, &req); err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInvalidParams, "Invalid parameters", nil)
	}
	
	result, err := h.server.ReadResource(ctx, &req)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handleListPrompts(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	result, err := h.server.ListPrompts(ctx)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handleGetPrompt(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	var req GetPromptRequest
	if err := h.unmarshalParams(msg.Params, &req); err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInvalidParams, "Invalid parameters", nil)
	}
	
	result, err := h.server.GetPrompt(ctx, &req)
	if err != nil {
		return NewErrorResponse(msg.ID, ErrorCodeInternalError, err.Error(), nil)
	}
	
	return NewResponse(msg.ID, result)
}

func (h *RequestHandler) handlePing(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	return NewResponse(msg.ID, map[string]interface{}{"pong": true})
}

func (h *RequestHandler) unmarshalParams(params interface{}, target interface{}) error {
	if params == nil {
		return nil
	}
	
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %w", err)
	}
	
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to unmarshal params: %w", err)
	}
	
	return nil
}