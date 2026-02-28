BINDIR  := bin
SERVER  := $(BINDIR)/ssl-server
AGENT   := $(BINDIR)/ssl-agent
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -s -w"

.PHONY: all build server agent linux clean install-server install-agent

all: build

build: server agent

server:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(SERVER) ./cmd/server
	@echo "✅  $(SERVER)"

agent:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(AGENT)  ./cmd/agent
	@echo "✅  $(AGENT)"

# 在 macOS 上交叉编译 Linux 二进制
linux:
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(SERVER)-linux ./cmd/server
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(AGENT)-linux  ./cmd/agent
	@echo "✅  Linux 二进制已生成"

clean:
	rm -rf $(BINDIR)

install-server: server
	install -m 755 $(SERVER) /usr/local/bin/ssl-server
	install -m 644 deploy/ssl-server.service /etc/systemd/system/
	mkdir -p /etc/ssl-manager /var/log/ssl-manager
	[ -f /etc/ssl-manager/server.yaml ] || cp configs/server.yaml /etc/ssl-manager/
	cp -r web /opt/ssl-manager/web
	systemctl daemon-reload
	@echo "✅  服务端已安装，修改 /etc/ssl-manager/server.yaml 后: systemctl start ssl-server"

install-agent: agent
	install -m 755 $(AGENT) /usr/local/bin/ssl-agent
	install -m 644 deploy/ssl-agent.service /etc/systemd/system/
	mkdir -p /etc/ssl-manager /var/log/ssl-manager /etc/nginx/ssl
	[ -f /etc/ssl-manager/agent.yaml ] || cp configs/agent.yaml /etc/ssl-manager/
	systemctl daemon-reload
	@echo "✅  Agent 已安装，修改 /etc/ssl-manager/agent.yaml 后: systemctl start ssl-agent"
