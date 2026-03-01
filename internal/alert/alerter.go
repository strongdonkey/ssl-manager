package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/yourorg/ssl-manager/internal/model"
	"go.uber.org/zap"
)

type Alerter struct {
	cfg    model.AlertConfig
	logger *zap.Logger
}

func New(cfg model.AlertConfig, logger *zap.Logger) *Alerter {
	return &Alerter{cfg: cfg, logger: logger}
}

// CheckExpiry 检查证书有效期并发告警
func (a *Alerter) CheckExpiry(metas []*model.CertMeta) {
	days := a.cfg.ExpireWarnDays
	if days <= 0 {
		days = 30
	}
	for _, m := range metas {
		remain := int(time.Until(m.NotAfter).Hours() / 24)
		if remain < 0 {
			a.Send(fmt.Sprintf("🚨 【证书已过期】\n域名: %s\n过期时间: %s\n已超期 %d 天",
				m.Domain, m.NotAfter.Format("2006-01-02"), -remain))
		} else if remain <= days {
			a.Send(fmt.Sprintf("⚠️ 【证书即将过期】\n域名: %s\n过期时间: %s\n剩余 %d 天",
				m.Domain, m.NotAfter.Format("2006-01-02"), remain))
		}
	}
}

func (a *Alerter) CertUpdated(domain, agentID string, version int64) {
	a.Send(fmt.Sprintf("✅ 【证书已更新】\n域名: %s\n服务器: %s\n版本: %d\n时间: %s",
		domain, agentID, version, time.Now().Format("2006-01-02 15:04:05")))
}

func (a *Alerter) CertUpdateFailed(domain, agentID string, err error) {
	a.Send(fmt.Sprintf("❌ 【证书更新失败】\n域名: %s\n服务器: %s\n错误: %v\n时间: %s",
		domain, agentID, err, time.Now().Format("2006-01-02 15:04:05")))
}

func (a *Alerter) Send(msg string) {
	a.logger.Info("告警", zap.String("msg", msg))
	if a.cfg.WebhookURL != "" {
		if a.cfg.Keywords != "" {
			// 如果配置了关键词，只有消息包含关键词才发送
			keywords := a.cfg.Keywords
			if !strings.Contains(msg, keywords) {
				msg = keywords + " " + msg // 自动添加关键词，确保消息能触发告警
			}
		}
		if err := a.dingTalk(msg); err != nil {
			a.logger.Error("webhook 发送失败", zap.Error(err))
		}
	}
	if a.cfg.EnableEmail && len(a.cfg.AlertEmails) > 0 {
		if err := a.email("SSL证书告警", msg); err != nil {
			a.logger.Error("邮件发送失败", zap.Error(err))
		}
	}
}

func (a *Alerter) dingTalk(content string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text":    map[string]string{"content": content},
	})
	resp, err := http.Post(a.cfg.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (a *Alerter) email(subject, body string) error {
	auth := smtp.PlainAuth("", a.cfg.SMTPUser, a.cfg.SMTPPassword, a.cfg.SMTPHost)
	msg := strings.Join([]string{
		"From: " + a.cfg.SMTPUser,
		"To: " + strings.Join(a.cfg.AlertEmails, ","),
		"Subject: " + subject,
		"Content-Type: text/plain; charset=UTF-8",
		"", body,
	}, "\r\n")
	addr := fmt.Sprintf("%s:%d", a.cfg.SMTPHost, a.cfg.SMTPPort)
	return smtp.SendMail(addr, auth, a.cfg.SMTPUser, a.cfg.AlertEmails, []byte(msg))
}
