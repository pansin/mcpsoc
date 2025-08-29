package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONRPCMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected JSONRPCMessage
		wantErr  bool
	}{
		{
			name:  "valid request message",
			input: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
			expected: JSONRPCMessage{
				JSONRPC: "2.0",
				ID:      float64(1),
				Method:  "initialize",
				Params: map[string]interface{}{
					"protocolVersion": "2025-06-18",
				},
			},
			wantErr: false,
		},
		{
			name:  "valid response message",
			input: `{"jsonrpc":"2.0","id":1,"result":{"status":"success"}}`,
			expected: JSONRPCMessage{
				JSONRPC: "2.0",
				ID:      float64(1),
				Result: map[string]interface{}{
					"status": "success",
				},
			},
			wantErr: false,
		},
		{
			name:  "error response message",
			input: `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
			expected: JSONRPCMessage{
				JSONRPC: "2.0",
				ID:      float64(1),
				Error: &RPCError{
					Code:    -32601,
					Message: "Method not found",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg JSONRPCMessage
			err := json.Unmarshal([]byte(tt.input), &msg)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.JSONRPC, msg.JSONRPC)
			assert.Equal(t, tt.expected.ID, msg.ID)
			assert.Equal(t, tt.expected.Method, msg.Method)

			if tt.expected.Params != nil {
				assert.Equal(t, tt.expected.Params, msg.Params)
			}

			if tt.expected.Result != nil {
				assert.Equal(t, tt.expected.Result, msg.Result)
			}

			if tt.expected.Error != nil {
				require.NotNil(t, msg.Error)
				assert.Equal(t, tt.expected.Error.Code, msg.Error.Code)
				assert.Equal(t, tt.expected.Error.Message, msg.Error.Message)
			}
		})
	}
}

func TestRPCError(t *testing.T) {
	err := &RPCError{
		Code:    ErrorCodeMethodNotFound,
		Message: "Method not found",
		Data:    "additional error data",
	}

	expected := "RPC error -32601: Method not found"
	assert.Equal(t, expected, err.Error())
}

func TestTool(t *testing.T) {
	tool := Tool{
		Name:        "test_tool",
		Description: "A test tool",
		InputSchema: JSONSchema{
			Type: "object",
			Properties: map[string]JSONSchema{
				"param1": {
					Type:        "string",
					Description: "First parameter",
				},
				"param2": {
					Type:        "integer",
					Description: "Second parameter",
				},
			},
			Required: []string{"param1"},
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(tool)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled Tool
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, tool.Name, unmarshaled.Name)
	assert.Equal(t, tool.Description, unmarshaled.Description)
	assert.Equal(t, tool.InputSchema.Type, unmarshaled.InputSchema.Type)
	assert.Equal(t, len(tool.InputSchema.Properties), len(unmarshaled.InputSchema.Properties))
	assert.Equal(t, tool.InputSchema.Required, unmarshaled.InputSchema.Required)
}

func TestResource(t *testing.T) {
	resource := Resource{
		URI:         "mcp://test/resource",
		Name:        "Test Resource",
		Description: "A test resource",
		MimeType:    "application/json",
	}

	// Test JSON marshaling
	data, err := json.Marshal(resource)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled Resource
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, resource, unmarshaled)
}

func TestInitializeRequest(t *testing.T) {
	req := InitializeRequest{
		ProtocolVersion: ProtocolVersion,
		Capabilities: ClientCapabilities{
			Experimental: map[string]interface{}{
				"feature1": true,
			},
		},
		ClientInfo: ClientInfo{
			Name:    "MCPSoc Test Client",
			Version: "1.0.0",
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(req)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled InitializeRequest
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, req.ProtocolVersion, unmarshaled.ProtocolVersion)
	assert.Equal(t, req.ClientInfo, unmarshaled.ClientInfo)
}

func TestServerCapabilities(t *testing.T) {
	caps := ServerCapabilities{
		Tools: &ToolsCapability{
			ListChanged: true,
		},
		Resources: &ResourcesCapability{
			Subscribe:   true,
			ListChanged: true,
		},
		Prompts: &PromptsCapability{
			ListChanged: false,
		},
		Logging: &LoggingCapability{},
	}

	// Test JSON marshaling
	data, err := json.Marshal(caps)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled ServerCapabilities
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	require.NotNil(t, unmarshaled.Tools)
	assert.Equal(t, caps.Tools.ListChanged, unmarshaled.Tools.ListChanged)

	require.NotNil(t, unmarshaled.Resources)
	assert.Equal(t, caps.Resources.Subscribe, unmarshaled.Resources.Subscribe)
	assert.Equal(t, caps.Resources.ListChanged, unmarshaled.Resources.ListChanged)

	require.NotNil(t, unmarshaled.Prompts)
	assert.Equal(t, caps.Prompts.ListChanged, unmarshaled.Prompts.ListChanged)

	require.NotNil(t, unmarshaled.Logging)
}

func TestToolResult(t *testing.T) {
	result := ToolResult{
		Content: []Content{
			{
				Type: "text",
				Text: "Test result",
			},
			{
				Type:     "image",
				Data:     "base64encodeddata",
				MimeType: "image/png",
			},
		},
		IsError: false,
	}

	// Test JSON marshaling
	data, err := json.Marshal(result)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled ToolResult
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, result.IsError, unmarshaled.IsError)
	assert.Equal(t, len(result.Content), len(unmarshaled.Content))

	for i, content := range result.Content {
		assert.Equal(t, content.Type, unmarshaled.Content[i].Type)
		assert.Equal(t, content.Text, unmarshaled.Content[i].Text)
		assert.Equal(t, content.Data, unmarshaled.Content[i].Data)
		assert.Equal(t, content.MimeType, unmarshaled.Content[i].MimeType)
	}
}

// Benchmark tests
func BenchmarkJSONRPCMessageMarshal(b *testing.B) {
	msg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test_method",
		Params: map[string]interface{}{
			"param1": "value1",
			"param2": 42,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSONRPCMessageUnmarshal(b *testing.B) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"test_method","params":{"param1":"value1","param2":42}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var msg JSONRPCMessage
		err := json.Unmarshal(data, &msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}