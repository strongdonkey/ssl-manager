package model

import "time"

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  etcd 存储结构（cert 和 key 分开存储）
//
//  Key 规则：
//    /ssl-manager/certs/{domain}/meta      → CertMeta   JSON（无私钥）
//    /ssl-manager/certs/{domain}/cert      → string（PEM）
//    /ssl-manager/certs/{domain}/key       → string（PEM，可单独设置 etcd 权限）
//    /ssl-manager/certs/{domain}/chain     → string（PEM，可选）
//    /ssl-manager/status/{agentID}/{domain}→ CertStatus JSON
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// CertMeta 证书元数据（不含证书内容，存于 /meta key）
type CertMeta struct {
	Domain      string    `json:"domain"`
	Version     int64     `json:"version"`      // 每次更新递增，Agent 用此判断是否需要拉取
	Fingerprint string    `json:"fingerprint"`  // SHA256 指纹，Agent 用于本地对比
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SANDomains  []string  `json:"san_domains"`
	HasChain    bool      `json:"has_chain"`    // 是否有中间链
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CertBundle 完整证书包（内存中使用，不直接存入 etcd）
type CertBundle struct {
	Meta     *CertMeta
	CertPEM  string
	KeyPEM   string
	ChainPEM string
}

// CertStatus 客户端上报的状态（存于 /status/ 前缀）
type CertStatus struct {
	Domain      string    `json:"domain"`
	AgentID     string    `json:"agent_id"`
	Fingerprint string    `json:"fingerprint"`  // 本地当前指纹
	Version     int64     `json:"version"`       // 本地当前版本
	LastSyncAt  time.Time `json:"last_sync_at"`
	NginxStatus string    `json:"nginx_status"` // running / stopped / unknown
	SyncOK      bool      `json:"sync_ok"`
	Error       string    `json:"error,omitempty"`
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  配置结构
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type EtcdConfig struct {
	Endpoints   []string `yaml:"endpoints"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	CACert      string   `yaml:"ca_cert"`
	ClientCert  string   `yaml:"client_cert"`
	ClientKey   string   `yaml:"client_key"`
	DialTimeout int      `yaml:"dial_timeout"` // 秒，默认 5
}

type AlertConfig struct {
	WebhookURL     string   `yaml:"webhook_url"`
	ExpireWarnDays int      `yaml:"expire_warn_days"` // 默认 30
	EnableEmail    bool     `yaml:"enable_email"`
	SMTPHost       string   `yaml:"smtp_host"`
	SMTPPort       int      `yaml:"smtp_port"`
	SMTPUser       string   `yaml:"smtp_user"`
	SMTPPassword   string   `yaml:"smtp_password"`
	AlertEmails    []string `yaml:"alert_emails"`
}

type ServerConfig struct {
	ListenAddr string      `yaml:"listen_addr"` // 默认 :8080
	EtcdConfig EtcdConfig  `yaml:"etcd"`
	Alert      AlertConfig `yaml:"alert"`
	LogLevel   string      `yaml:"log_level"`
	LogFile    string      `yaml:"log_file"`
	APIToken   string      `yaml:"api_token"` // 简单 Bearer Token 鉴权（可选）
}

type AgentConfig struct {
	AgentID        string     `yaml:"agent_id"`          // 默认 hostname
	EtcdConfig     EtcdConfig `yaml:"etcd"`
	NginxReloadCmd string     `yaml:"nginx_reload_cmd"`  // 默认 nginx -s reload
	CertBaseDir    string     `yaml:"cert_base_dir"`     // 默认 /etc/nginx/ssl
	Domains        []string   `yaml:"domains"`           // 空=同步全部
	PollInterval   int        `yaml:"poll_interval"`     // 秒，默认 300
	LogLevel       string     `yaml:"log_level"`
	LogFile        string     `yaml:"log_file"`
	DryRun         bool       `yaml:"dry_run"`
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  API 响应
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func OK(data interface{}) APIResponse {
	return APIResponse{Code: 0, Message: "ok", Data: data}
}
func Err(code int, msg string) APIResponse {
	return APIResponse{Code: code, Message: msg}
}
