package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	certmgr "github.com/yourorg/ssl-manager/internal/cert"
	etcdclient "github.com/yourorg/ssl-manager/internal/etcd"
	"github.com/yourorg/ssl-manager/internal/model"
	"github.com/yourorg/ssl-manager/internal/nginx"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func main() {
	cfgPath := flag.String("config", "/etc/ssl-manager/agent.yaml", "配置文件路径")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogLevel, cfg.LogFile)
	defer logger.Sync()

	logger.Info("SSL Agent 启动",
		zap.String("agent_id", cfg.AgentID),
		zap.Strings("domains", cfg.Domains),
		zap.Int("poll_interval", cfg.PollInterval),
		zap.Bool("dry_run", cfg.DryRun),
	)

	etcd, err := etcdclient.New(cfg.EtcdConfig, logger)
	if err != nil {
		logger.Fatal("连接 etcd 失败", zap.Error(err))
	}
	defer etcd.Close()

	agent := &Agent{
		cfg:    cfg,
		etcd:   etcd,
		cert:   certmgr.New(cfg.CertBaseDir, logger),
		nginx:  nginx.New(cfg.NginxReloadCmd, logger),
		logger: logger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-quit; cancel() }()

	agent.Run(ctx)
	logger.Info("Agent 已退出")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type Agent struct {
	cfg    *model.AgentConfig
	etcd   *etcdclient.Client
	cert   *certmgr.Manager
	nginx  *nginx.Manager
	logger *zap.Logger
}

// Run 主循环：启动时立即同步，然后按 poll_interval 轮询
func (a *Agent) Run(ctx context.Context) {
	interval := time.Duration(a.cfg.PollInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	// 立即执行一次
	a.syncAll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.logger.Debug("轮询触发同步", zap.Duration("interval", interval))
			a.syncAll(ctx)
		}
	}
}

// syncAll 全量对比 + 按需更新
func (a *Agent) syncAll(ctx context.Context) {
	syncCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// 确定要检查的域名列表
	domains := a.cfg.Domains
	if len(domains) == 0 {
		metas, err := a.etcd.ListMeta(syncCtx)
		if err != nil {
			a.logger.Error("获取证书列表失败", zap.Error(err))
			return
		}
		for _, m := range metas {
			domains = append(domains, m.Domain)
		}
	}

	needReload := false

	for _, domain := range domains {
		// 只拉取版本号和指纹（轻量）
		remoteVer, remoteFP, err := a.etcd.GetMetaVersion(syncCtx, domain)
		if err != nil {
			a.logger.Error("获取版本信息失败", zap.String("domain", domain), zap.Error(err))
			continue
		}
		if remoteVer == 0 {
			a.logger.Warn("etcd 中不存在该域名", zap.String("domain", domain))
			continue
		}

		// 对比本地：版本号 + 指纹
		needUpdate, err := a.cert.NeedsUpdate(domain, remoteVer, remoteFP)
		if err != nil {
			a.logger.Error("检查更新失败", zap.String("domain", domain), zap.Error(err))
			continue
		}
		if !needUpdate {
			a.logger.Debug("证书无需更新", zap.String("domain", domain), zap.Int64("version", remoteVer))
			continue
		}

		// 拉取完整证书包（含私钥）
		a.logger.Info("发现新版证书，开始拉取",
			zap.String("domain", domain),
			zap.Int64("remote_version", remoteVer),
		)
		bundle, err := a.etcd.GetBundle(syncCtx, domain)
		if err != nil || bundle == nil {
			a.logger.Error("拉取证书失败", zap.String("domain", domain), zap.Error(err))
			a.reportStatus(domain, remoteVer, remoteFP, err)
			continue
		}

		// 写入本地文件
		if err := a.cert.WriteCert(bundle, a.cfg.DryRun); err != nil {
			a.logger.Error("写入证书文件失败", zap.String("domain", domain), zap.Error(err))
			a.reportStatus(domain, remoteVer, remoteFP, err)
			continue
		}

		needReload = true
		a.reportStatus(domain, remoteVer, remoteFP, nil)
		a.logger.Info("证书更新成功", zap.String("domain", domain), zap.Int64("version", remoteVer))
	}

	// 所有域名处理完毕后，统一 reload（防抖：避免多域名触发多次 reload）
	if needReload {
		a.logger.Info("证书有更新，执行 nginx reload")
		if err := a.nginx.Reload(a.cfg.DryRun); err != nil {
			a.logger.Error("nginx reload 失败", zap.Error(err))
		}
	}
}

func (a *Agent) reportStatus(domain string, version int64, fp string, applyErr error) {
	status := &model.CertStatus{
		Domain:      domain,
		AgentID:     a.cfg.AgentID,
		Version:     version,
		Fingerprint: fp,
		LastSyncAt:  time.Now(),
		NginxStatus: a.nginx.Status(),
		SyncOK:      applyErr == nil,
	}
	if applyErr != nil {
		status.Error = applyErr.Error()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.etcd.PutStatus(ctx, status); err != nil {
		a.logger.Warn("上报状态失败", zap.Error(err))
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func loadConfig(path string) (*model.AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg model.AgentConfig
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.AgentID == "" {
		cfg.AgentID, _ = os.Hostname()
	}
	if cfg.CertBaseDir == "" {
		cfg.CertBaseDir = "/etc/nginx/ssl"
	}
	if cfg.NginxReloadCmd == "" {
		cfg.NginxReloadCmd = "nginx -s reload"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 300
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
	l, _ := cfg.Build()
	return l
}
