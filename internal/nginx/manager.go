package nginx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Manager struct {
	reloadCmd string
	logger    *zap.Logger
}

func New(cmd string, logger *zap.Logger) *Manager {
	if cmd == "" {
		cmd = "nginx -s reload"
	}
	return &Manager{reloadCmd: cmd, logger: logger}
}

func (m *Manager) Test() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t 失败: %s\n%s", err, out)
	}
	return nil
}

func (m *Manager) Reload(dryRun bool) error {
	if dryRun {
		m.logger.Info("[DryRun] 跳过 nginx reload")
		return nil
	}
	if err := m.Test(); err != nil {
		return fmt.Errorf("配置校验失败，放弃 reload: %w", err)
	}
	parts := strings.Fields(m.reloadCmd)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if len(parts) == 1 {
		cmd = exec.CommandContext(ctx, parts[0])
	} else {
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload 失败: %s\n%s", err, out)
	}
	m.logger.Info("nginx reload 成功", zap.String("cmd", m.reloadCmd))
	return nil
}

func (m *Manager) Status() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "pidof", "nginx").Run(); err == nil {
		return "running"
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	out, err := exec.CommandContext(ctx2, "systemctl", "is-active", "nginx").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "unknown"
}
