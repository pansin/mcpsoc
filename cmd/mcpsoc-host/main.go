package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/internal/api"
	"github.com/mcpsoc/mcpsoc/internal/config"
	"github.com/mcpsoc/mcpsoc/internal/logger"
	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/mcpsoc/mcpsoc/internal/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "mcpsoc-host",
		Short: "MCPSoc Host - MCP协议驱动的智能安全运营中心",
		Long: `MCPSoc Host是基于MCP协议的开放式智能安全运营中心的核心服务。
它负责协调各种MCP Server，处理安全查询，并提供AI驱动的威胁分析能力。`,
		Run: runServer,
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("MCPSoc Host\n")
			fmt.Printf("Version: %s\n", Version)
			fmt.Printf("Build Time: %s\n", BuildTime)
			fmt.Printf("Git Commit: %s\n", GitCommit)
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.PersistentFlags().StringP("config", "c", "config/config.yaml", "配置文件路径")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "日志级别 (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// 获取配置文件路径
	configPath, _ := cmd.Flags().GetString("config")
	logLevel, _ := cmd.Flags().GetString("log-level")

	// 初始化配置
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	log := logger.New(logLevel)
	log.WithFields(logrus.Fields{
		"version":    Version,
		"build_time": BuildTime,
		"git_commit": GitCommit,
	}).Info("Starting MCPSoc Host")

	// 初始化数据库
	db, err := storage.NewDatabase(cfg.Database)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize database")
	}
	defer db.Close()

	// 初始化MCP管理器
	mcpManager := mcp.NewManager(log)

	// 初始化API路由
	router := setupRouter(cfg, log, db, mcpManager)

	// 创建HTTP服务器
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: router,
	}

	// 启动服务器
	go func() {
		log.WithField("port", cfg.Server.Port).Info("Starting HTTP server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.WithError(err).Fatal("Server forced to shutdown")
	}

	log.Info("Server exited")
}

func setupRouter(cfg *config.Config, log *logrus.Logger, db storage.Database, mcpManager *mcp.Manager) *gin.Engine {
	// 设置Gin模式
	if cfg.Server.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// 中间件
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": Version,
			"time":    time.Now().UTC(),
		})
	})

	// API路由
	apiHandler := api.NewHandler(log, db, mcpManager)
	v1 := router.Group("/api/v1")
	{
		v1.POST("/query/natural", apiHandler.HandleNaturalQuery)
		v1.POST("/query/structured", apiHandler.HandleStructuredQuery)
		v1.GET("/mcp/servers", apiHandler.ListMCPServers)
		v1.GET("/mcp/servers/:id", apiHandler.GetMCPServer)
		v1.POST("/mcp/servers/:id/tools/:tool", apiHandler.CallMCPTool)
	}

	return router
}