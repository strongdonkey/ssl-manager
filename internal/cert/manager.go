package cert

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/strongdonkey/ssl-manager/internal/model"
	"go.uber.org/zap"
)

type Manager struct {
	baseDir string
	logger  *zap.Logger
}

func New(baseDir string, logger *zap.Logger) *Manager {
	return &Manager{baseDir: baseDir, logger: logger}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  本地文件操作
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// LocalVersion 读取本地保存的版本号（存在 .version 文件中）
func (m *Manager) LocalVersion(domain string) int64 {
	versionFile := filepath.Join(m.baseDir, domain, ".version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return 0
	}
	var v int64
	fmt.Sscanf(string(data), "%d", &v)
	return v
}

// LocalFingerprint 读取本地证书 SHA256 指纹
func (m *Manager) LocalFingerprint(domain string) (string, error) {
	data, err := os.ReadFile(filepath.Join(m.baseDir, domain, "cert.pem"))
	if err != nil {
		return "", err
	}
	return FingerprintPEM(data)
}

// NeedsUpdate 与 etcd meta 对比，判断是否需要更新
// 优先对比版本号（快），版本相同再对比指纹（防止手动修改）
func (m *Manager) NeedsUpdate(domain string, remoteVersion int64, remoteFingerprint string) (bool, error) {
	localVersion := m.LocalVersion(domain)
	if localVersion < remoteVersion {
		return true, nil
	}
	// 版本相同时做指纹兜底校验
	localFP, err := m.LocalFingerprint(domain)
	if err != nil {
		return true, nil // 本地不存在，需要更新
	}
	return localFP != remoteFingerprint, nil
}

// WriteCert 原子写入证书文件，写前备份
func (m *Manager) WriteCert(bundle *model.CertBundle, dryRun bool) error {
	domain := bundle.Meta.Domain
	dir := filepath.Join(m.baseDir, domain)

	if dryRun {
		m.logger.Info("[DryRun] 跳过写入", zap.String("domain", domain), zap.String("dir", dir))
		return nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 备份旧证书
	m.backup(domain)

	// 写文件（先 tmp 再 rename 保证原子性）
	type fileEntry struct {
		name string
		data string
		perm os.FileMode
	}
	files := []fileEntry{
		{"cert.pem", bundle.CertPEM, 0644},
		{"key.pem", bundle.KeyPEM, 0600},
	}
	if bundle.ChainPEM != "" {
		files = append(files,
			fileEntry{"chain.pem", bundle.ChainPEM, 0644},
			fileEntry{"fullchain.pem", bundle.CertPEM + "\n" + bundle.ChainPEM, 0644},
		)
	}

	for _, f := range files {
		dst := filepath.Join(dir, f.name)
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, []byte(f.data), f.perm); err != nil {
			return fmt.Errorf("写临时文件失败 %s: %w", f.name, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			return fmt.Errorf("rename 失败 %s: %w", f.name, err)
		}
	}

	// 保存版本号
	_ = os.WriteFile(
		filepath.Join(dir, ".version"),
		[]byte(fmt.Sprintf("%d", bundle.Meta.Version)),
		0644,
	)

	m.logger.Info("证书文件更新成功",
		zap.String("domain", domain),
		zap.Int64("version", bundle.Meta.Version),
		zap.String("expires", bundle.Meta.NotAfter.Format("2006-01-02")),
	)
	return nil
}

func (m *Manager) backup(domain string) {
	src := filepath.Join(m.baseDir, domain, "cert.pem")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return
	}
	backupDir := filepath.Join(m.baseDir, domain, "backup", time.Now().Format("20060102_150405"))
	_ = os.MkdirAll(backupDir, 0755)
	for _, name := range []string{"cert.pem", "key.pem", "chain.pem", "fullchain.pem"} {
		data, err := os.ReadFile(filepath.Join(m.baseDir, domain, name))
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(backupDir, name), data, 0600)
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  证书解析工具
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func ParsePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("无法解析 PEM 数据")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ValidateCertKey(certPEM, keyPEM string) error {
	_, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("证书与私钥不匹配: %w", err)
	}
	return nil
}

func FingerprintPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("无法解析 PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	fp := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fp[:]), nil
}

func ExtractMeta(certPEM string) (notBefore, notAfter time.Time, sans []string, err error) {
	cert, err := ParsePEM(certPEM)
	if err != nil {
		return
	}
	return cert.NotBefore, cert.NotAfter, cert.DNSNames, nil
}
