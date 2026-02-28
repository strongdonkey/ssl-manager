package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourorg/ssl-manager/internal/alert"
	"github.com/yourorg/ssl-manager/internal/api"
	etcdclient "github.com/yourorg/ssl-manager/internal/etcd"
	"github.com/yourorg/ssl-manager/internal/model"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func main() {
	cfgPath := flag.String("config", "/etc/ssl-manager/server.yaml", "配置文件路径")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogLevel, cfg.LogFile)
	defer logger.Sync()

	logger.Info("SSL Manager 服务端启动", zap.String("listen", cfg.ListenAddr))

	etcd, err := etcdclient.New(cfg.EtcdConfig, logger)
	if err != nil {
		logger.Fatal("etcd 连接失败", zap.Error(err))
	}
	defer etcd.Close()

	alerter := alert.New(cfg.Alert, logger)
	go runExpireCheck(etcd, alerter, logger)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), requestLog(logger))

	// 注册 CORS（方便 Web UI 开发阶段跨域）
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	handler := api.NewHandler(etcd, cfg.APIToken, logger)
	handler.RegisterRoutes(r)

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: r}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		logger.Info("HTTP 服务启动", zap.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP 服务异常", zap.Error(err))
		}
	}()

	<-quit
	logger.Info("正在优雅退出...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	logger.Info("服务已退出")
}

func runExpireCheck(etcd *etcdclient.Client, a *alert.Alerter, logger *zap.Logger) {
	check := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		metas, err := etcd.ListMeta(ctx)
		if err != nil {
			logger.Error("获取证书列表失败", zap.Error(err))
			return
		}
		a.CheckExpiry(metas)
	}
	check()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		check()
	}
}

func requestLog(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		c.Next()
		logger.Info("req",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(t)),
		)
	}
}

func loadConfig(path string) (*model.ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg model.ServerConfig
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	return &cfg, nil
}

func newLogger(level, file string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	if level == "debug" {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	if file != "" {
		cfg.OutputPaths = []string{file, "stdout"}
		cfg.ErrorOutputPaths = []string{file, "stderr"}
	}
	l, err := cfg.Build()
	if err != nil {
		// 文件输出失败时回退到控制台输出
		cfg.OutputPaths = []string{"stdout"}
		cfg.ErrorOutputPaths = []string{"stderr"}
		l, _ = cfg.Build()
	}
	return l
}
