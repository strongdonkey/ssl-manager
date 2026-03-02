package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/strongdonkey/ssl-manager/internal/model"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

// etcd key 布局：
//
//	/ssl-manager/certs/{domain}/meta   → CertMeta JSON
//	/ssl-manager/certs/{domain}/cert   → cert PEM 字符串
//	/ssl-manager/certs/{domain}/key    → key  PEM 字符串（建议单独设 etcd RBAC）
//	/ssl-manager/certs/{domain}/chain  → chain PEM 字符串（可选）
//	/ssl-manager/status/{agentID}/{domain} → CertStatus JSON
const (
	CertPrefix   = "/ssl-manager/certs/"
	StatusPrefix = "/ssl-manager/status/"
)

func certKey(domain, field string) string {
	return CertPrefix + domain + "/" + field
}

// Client etcd 封装
type Client struct {
	cli    *clientv3.Client
	logger *zap.Logger
}

func New(cfg model.EtcdConfig, logger *zap.Logger) (*Client, error) {
	timeout := time.Duration(cfg.DialTimeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	etcdCfg := clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: timeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
	}
	if cfg.CACert != "" {
		tlsCfg, err := buildTLS(cfg)
		if err != nil {
			return nil, err
		}
		etcdCfg.TLS = tlsCfg
	}
	cli, err := clientv3.New(etcdCfg)
	if err != nil {
		return nil, fmt.Errorf("连接 etcd 失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err = cli.Status(ctx, cfg.Endpoints[0]); err != nil {
		return nil, fmt.Errorf("etcd 连通性检查失败: %w", err)
	}
	logger.Info("etcd 连接成功", zap.Strings("endpoints", cfg.Endpoints))
	return &Client{cli: cli, logger: logger}, nil
}

func (c *Client) Close() { _ = c.cli.Close() }

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  写入证书（cert/key/chain 分开存储，使用 Txn 原子提交）
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func (c *Client) PutCert(ctx context.Context, bundle *model.CertBundle) error {
	metaBytes, err := json.Marshal(bundle.Meta)
	if err != nil {
		return err
	}

	// 构建事务操作列表
	ops := []clientv3.Op{
		clientv3.OpPut(certKey(bundle.Meta.Domain, "meta"), string(metaBytes)),
		clientv3.OpPut(certKey(bundle.Meta.Domain, "cert"), bundle.CertPEM),
		clientv3.OpPut(certKey(bundle.Meta.Domain, "key"), bundle.KeyPEM),
	}
	if bundle.ChainPEM != "" {
		ops = append(ops, clientv3.OpPut(certKey(bundle.Meta.Domain, "chain"), bundle.ChainPEM))
	}

	// 使用事务保证原子性（要么全部成功，要么全部失败）
	txn := c.cli.Txn(ctx)
	resp, err := txn.Then(ops...).Commit()
	if err != nil {
		return fmt.Errorf("etcd 事务写入失败: %w", err)
	}
	if !resp.Succeeded {
		return fmt.Errorf("etcd 事务未成功提交")
	}

	c.logger.Info("证书写入 etcd 成功",
		zap.String("domain", bundle.Meta.Domain),
		zap.Int64("version", bundle.Meta.Version),
		zap.Bool("has_chain", bundle.ChainPEM != ""),
	)
	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  读取证书
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GetMeta 仅读取元数据（无私钥，供展示用）
func (c *Client) GetMeta(ctx context.Context, domain string) (*model.CertMeta, error) {
	resp, err := c.cli.Get(ctx, certKey(domain, "meta"))
	if err != nil || len(resp.Kvs) == 0 {
		return nil, err
	}
	var meta model.CertMeta
	return &meta, json.Unmarshal(resp.Kvs[0].Value, &meta)
}

// GetBundle 读取完整证书包（含私钥，供 agent 同步用）
func (c *Client) GetBundle(ctx context.Context, domain string) (*model.CertBundle, error) {
	// 一次性读取 domain/ 前缀下所有 key
	prefix := CertPrefix + domain + "/"
	resp, err := c.cli.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}

	bundle := &model.CertBundle{}
	for _, kv := range resp.Kvs {
		field := strings.TrimPrefix(string(kv.Key), prefix)
		switch field {
		case "meta":
			var meta model.CertMeta
			if err = json.Unmarshal(kv.Value, &meta); err != nil {
				return nil, err
			}
			bundle.Meta = &meta
		case "cert":
			bundle.CertPEM = string(kv.Value)
		case "key":
			bundle.KeyPEM = string(kv.Value)
		case "chain":
			bundle.ChainPEM = string(kv.Value)
		}
	}
	if bundle.Meta == nil {
		return nil, fmt.Errorf("证书 meta 数据缺失")
	}
	return bundle, nil
}

// ListMeta 列出所有证书元数据（无私钥）
func (c *Client) ListMeta(ctx context.Context) ([]*model.CertMeta, error) {
	resp, err := c.cli.Get(ctx, CertPrefix, clientv3.WithPrefix(),
		clientv3.WithRange(clientv3.GetPrefixRangeEnd(CertPrefix)))
	if err != nil {
		return nil, err
	}

	var metas []*model.CertMeta
	for _, kv := range resp.Kvs {
		// 只处理 /meta 结尾的 key
		if !strings.HasSuffix(string(kv.Key), "/meta") {
			continue
		}
		var meta model.CertMeta
		if err = json.Unmarshal(kv.Value, &meta); err != nil {
			c.logger.Warn("解析 meta 失败", zap.String("key", string(kv.Key)))
			continue
		}
		metas = append(metas, &meta)
	}
	return metas, nil
}

// DeleteCert 删除域名下所有 key
func (c *Client) DeleteCert(ctx context.Context, domain string) error {
	prefix := CertPrefix + domain + "/"
	_, err := c.cli.Delete(ctx, prefix, clientv3.WithPrefix())
	return err
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  定时轮询：Agent 用于对比本地版本
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GetMetaVersion 快速获取版本号（轮询时只读 meta，减少 IO）
func (c *Client) GetMetaVersion(ctx context.Context, domain string) (int64, string, error) {
	meta, err := c.GetMeta(ctx, domain)
	if err != nil || meta == nil {
		return 0, "", err
	}
	return meta.Version, meta.Fingerprint, nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Agent 状态上报
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func (c *Client) PutStatus(ctx context.Context, status *model.CertStatus, ttl int64) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 900
	}
	// 带 TTL 的 Lease：agent 停止后自动过期，TTL 应大于 poll_interval
	lease, err := c.cli.Grant(ctx, ttl)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s%s/%s", StatusPrefix, status.AgentID, status.Domain)
	_, err = c.cli.Put(ctx, key, string(data), clientv3.WithLease(lease.ID))
	return err
}

func (c *Client) ListStatus(ctx context.Context) ([]*model.CertStatus, error) {
	resp, err := c.cli.Get(ctx, StatusPrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	var list []*model.CertStatus
	for _, kv := range resp.Kvs {
		var s model.CertStatus
		if err = json.Unmarshal(kv.Value, &s); err != nil {
			continue
		}
		list = append(list, &s)
	}
	return list, nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  TLS helper
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func buildTLS(cfg model.EtcdConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{}
	if cfg.CACert != "" {
		data, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(data)
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}
