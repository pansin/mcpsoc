package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config 应用配置结构
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	MCP      MCPConfig      `mapstructure:"mcp"`
	AI       AIConfig       `mapstructure:"ai"`
	Security SecurityConfig `mapstructure:"security"`
}

// ServerConfig HTTP服务器配置
type ServerConfig struct {
	Port  int  `mapstructure:"port"`
	Debug bool `mapstructure:"debug"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// MCPConfig MCP协议配置
type MCPConfig struct {
	Servers []MCPServerConfig `mapstructure:"servers"`
}

// MCPServerConfig MCP服务器配置
type MCPServerConfig struct {
	ID          string            `mapstructure:"id"`
	Name        string            `mapstructure:"name"`
	Type        string            `mapstructure:"type"`
	Transport   string            `mapstructure:"transport"`
	Endpoint    string            `mapstructure:"endpoint"`
	Credentials map[string]string `mapstructure:"credentials"`
	Enabled     bool              `mapstructure:"enabled"`
}

// AIConfig AI服务配置
type AIConfig struct {
	Providers []AIProviderConfig `mapstructure:"providers"`
	Default   string             `mapstructure:"default"`
}

// AIProviderConfig AI提供商配置
type AIProviderConfig struct {
	Name   string `mapstructure:"name"`
	Type   string `mapstructure:"type"`
	APIKey string `mapstructure:"api_key"`
	Model  string `mapstructure:"model"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	JWTSecret string `mapstructure:"jwt_secret"`
	APIKeys   []string `mapstructure:"api_keys"`
}

// Load 加载配置文件
func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// 设置环境变量前缀
	viper.SetEnvPrefix("MCPSOC")
	viper.AutomaticEnv()

	// 设置默认值
	setDefaults()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// 配置文件不存在，使用默认配置
			fmt.Printf("Config file not found, using defaults: %s\n", configPath)
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// 从环境变量覆盖敏感配置
	if dbPassword := os.Getenv("MCPSOC_DATABASE_PASSWORD"); dbPassword != "" {
		config.Database.Password = dbPassword
	}
	if jwtSecret := os.Getenv("MCPSOC_JWT_SECRET"); jwtSecret != "" {
		config.Security.JWTSecret = jwtSecret
	}

	return &config, nil
}

// setDefaults 设置默认配置值
func setDefaults() {
	// 服务器默认配置
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.debug", false)

	// 数据库默认配置
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "mcpsoc")
	viper.SetDefault("database.database", "mcpsoc")
	viper.SetDefault("database.ssl_mode", "disable")

	// MCP默认配置
	viper.SetDefault("mcp.servers", []MCPServerConfig{})

	// AI默认配置
	viper.SetDefault("ai.default", "openai")
	viper.SetDefault("ai.providers", []AIProviderConfig{
		{
			Name:  "openai",
			Type:  "openai",
			Model: "gpt-4",
		},
	})

	// 安全默认配置
	viper.SetDefault("security.jwt_secret", "change-me-in-production")
}

// GetDSN 获取数据库连接字符串
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode)
}