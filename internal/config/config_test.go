package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultConfig(t *testing.T) {
	// 创建临时配置文件
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	
	// 创建基本配置文件
	configContent := `
server:
  port: 9090
  debug: true

database:
  host: "test-host"
  port: 5433
  user: "test-user"
  database: "test-db"
  ssl_mode: "require"

ai:
  default: "claude"
  providers:
    - name: "claude"
      type: "anthropic"
      model: "claude-3-sonnet"

security:
  jwt_secret: "test-secret"
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// 加载配置
	config, err := Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, config)

	// 验证服务器配置
	assert.Equal(t, 9090, config.Server.Port)
	assert.True(t, config.Server.Debug)

	// 验证数据库配置
	assert.Equal(t, "test-host", config.Database.Host)
	assert.Equal(t, 5433, config.Database.Port)
	assert.Equal(t, "test-user", config.Database.User)
	assert.Equal(t, "test-db", config.Database.Database)
	assert.Equal(t, "require", config.Database.SSLMode)

	// 验证AI配置
	assert.Equal(t, "claude", config.AI.Default)
	require.Len(t, config.AI.Providers, 1)
	assert.Equal(t, "claude", config.AI.Providers[0].Name)
	assert.Equal(t, "anthropic", config.AI.Providers[0].Type)

	// 验证安全配置
	assert.Equal(t, "test-secret", config.Security.JWTSecret)
}

func TestLoad_NonExistentFile(t *testing.T) {
	// 尝试加载不存在的配置文件
	config, err := Load("/nonexistent/config.yaml")
	
	// 应该使用默认配置，不报错
	require.NoError(t, err)
	require.NotNil(t, config)

	// 验证默认值
	assert.Equal(t, 8080, config.Server.Port)
	assert.False(t, config.Server.Debug)
	assert.Equal(t, "localhost", config.Database.Host)
	assert.Equal(t, 5432, config.Database.Port)
}

func TestLoad_InvalidYAML(t *testing.T) {
	// 创建临时配置文件
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	
	// 创建无效的YAML文件
	invalidContent := `
server:
  port: invalid_port
  debug: not_boolean
[invalid yaml structure
`
	
	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	require.NoError(t, err)

	// 加载配置应该失败
	config, err := Load(configPath)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoad_EnvironmentVariableOverride(t *testing.T) {
	// 设置环境变量
	originalPassword := os.Getenv("MCPSOC_DATABASE_PASSWORD")
	originalSecret := os.Getenv("MCPSOC_JWT_SECRET")
	
	defer func() {
		// 恢复原始环境变量
		os.Setenv("MCPSOC_DATABASE_PASSWORD", originalPassword)
		os.Setenv("MCPSOC_JWT_SECRET", originalSecret)
	}()

	os.Setenv("MCPSOC_DATABASE_PASSWORD", "env-password")
	os.Setenv("MCPSOC_JWT_SECRET", "env-secret")

	// 创建临时配置文件
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	
	configContent := `
database:
  password: "file-password"
security:
  jwt_secret: "file-secret"
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// 加载配置
	config, err := Load(configPath)
	require.NoError(t, err)

	// 验证环境变量覆盖了配置文件
	assert.Equal(t, "env-password", config.Database.Password)
	assert.Equal(t, "env-secret", config.Security.JWTSecret)
}

func TestLoad_MCPServerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	
	configContent := `
mcp:
  servers:
    - id: "firewall-01"
      name: "pfSense Firewall"
      type: "firewall"
      transport: "websocket"
      endpoint: "ws://localhost:8081"
      enabled: true
      credentials:
        username: "admin"
        password: "secret"
    - id: "waf-01"
      name: "ModSecurity WAF"
      type: "waf"
      transport: "http"
      endpoint: "http://localhost:8082"
      enabled: false
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	config, err := Load(configPath)
	require.NoError(t, err)

	require.Len(t, config.MCP.Servers, 2)

	// 验证第一个服务器
	server1 := config.MCP.Servers[0]
	assert.Equal(t, "firewall-01", server1.ID)
	assert.Equal(t, "pfSense Firewall", server1.Name)
	assert.Equal(t, "firewall", server1.Type)
	assert.Equal(t, "websocket", server1.Transport)
	assert.Equal(t, "ws://localhost:8081", server1.Endpoint)
	assert.True(t, server1.Enabled)
	assert.Equal(t, "admin", server1.Credentials["username"])
	assert.Equal(t, "secret", server1.Credentials["password"])

	// 验证第二个服务器
	server2 := config.MCP.Servers[1]
	assert.Equal(t, "waf-01", server2.ID)
	assert.False(t, server2.Enabled)
}

func TestDatabaseConfig_GetDSN(t *testing.T) {
	config := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		Database: "testdb",
		SSLMode:  "disable",
	}

	expectedDSN := "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=disable"
	assert.Equal(t, expectedDSN, config.GetDSN())
}

func TestDatabaseConfig_GetDSN_WithSpecialChars(t *testing.T) {
	config := DatabaseConfig{
		Host:     "db.example.com",
		Port:     5433,
		User:     "user@domain",
		Password: "pass with spaces",
		Database: "my-db",
		SSLMode:  "require",
	}

	dsn := config.GetDSN()
	assert.Contains(t, dsn, "host=db.example.com")
	assert.Contains(t, dsn, "port=5433")
	assert.Contains(t, dsn, "user=user@domain")
	assert.Contains(t, dsn, "password=pass with spaces")
	assert.Contains(t, dsn, "dbname=my-db")
	assert.Contains(t, dsn, "sslmode=require")
}

func TestAIConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  AIConfig
		wantErr bool
	}{
		{
			name: "valid openai config",
			config: AIConfig{
				Default: "openai",
				Providers: []AIProviderConfig{
					{
						Name:   "openai",
						Type:   "openai",
						APIKey: "sk-test",
						Model:  "gpt-4",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid anthropic config",
			config: AIConfig{
				Default: "claude",
				Providers: []AIProviderConfig{
					{
						Name:   "claude",
						Type:   "anthropic",
						APIKey: "claude-test",
						Model:  "claude-3-sonnet",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing default provider",
			config: AIConfig{
				Default: "nonexistent",
				Providers: []AIProviderConfig{
					{
						Name: "openai",
						Type: "openai",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAIConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function for AI config validation
func validateAIConfig(config AIConfig) error {
	// 检查默认提供商是否存在
	found := false
	for _, provider := range config.Providers {
		if provider.Name == config.Default {
			found = true
			break
		}
	}
	if !found {
		return assert.AnError
	}
	return nil
}

// Benchmark tests
func BenchmarkLoad(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	
	configContent := `
server:
  port: 8080
database:
  host: localhost
`
	
	os.WriteFile(configPath, []byte(configContent), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, err := Load(configPath)
		if err != nil {
			b.Fatal(err)
		}
		_ = config
	}
}

func BenchmarkGetDSN(b *testing.B) {
	config := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		Database: "testdb",
		SSLMode:  "disable",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dsn := config.GetDSN()
		_ = dsn
	}
}