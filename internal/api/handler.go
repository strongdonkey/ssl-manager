package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourorg/ssl-manager/internal/cert"
	etcdclient "github.com/yourorg/ssl-manager/internal/etcd"
	"github.com/yourorg/ssl-manager/internal/model"
	"go.uber.org/zap"
)

type Handler struct {
	etcd   *etcdclient.Client
	logger *zap.Logger
	token  string // Bearer Token 鉴权（可选）
}

func NewHandler(etcd *etcdclient.Client, token string, logger *zap.Logger) *Handler {
	return &Handler{etcd: etcd, token: token, logger: logger}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	// 静态文件 Web UI
	r.Static("/ui", "./web")
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/ui") })

	v1 := r.Group("/api/v1")
	if h.token != "" {
		v1.Use(h.authMiddleware())
	}
	{
		v1.GET("/certs", h.ListCerts)
		v1.GET("/certs/:domain", h.GetCert)
		v1.POST("/certs", h.UpsertCert)
		v1.DELETE("/certs/:domain", h.DeleteCert)
		v1.GET("/agents", h.ListAgents)
		v1.GET("/health", h.Health)
	}
}

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token != "Bearer "+h.token {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.Err(401, "未授权"))
			return
		}
		c.Next()
	}
}

// GET /api/v1/certs
func (h *Handler) ListCerts(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	metas, err := h.etcd.ListMeta(ctx)
	if err != nil {
		c.JSON(500, model.Err(500, err.Error()))
		return
	}
	c.JSON(200, model.OK(metas))
}

// GET /api/v1/certs/:domain
func (h *Handler) GetCert(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	meta, err := h.etcd.GetMeta(ctx, c.Param("domain"))
	if err != nil {
		c.JSON(500, model.Err(500, err.Error()))
		return
	}
	if meta == nil {
		c.JSON(404, model.Err(404, "证书不存在"))
		return
	}
	c.JSON(200, model.OK(meta))
}

type UpsertRequest struct {
	Domain      string `json:"domain" binding:"required"`
	CertPEM     string `json:"cert_pem" binding:"required"`
	KeyPEM      string `json:"key_pem" binding:"required"`
	ChainPEM    string `json:"chain_pem"`
	Description string `json:"description"`
}

// POST /api/v1/certs
func (h *Handler) UpsertCert(c *gin.Context) {
	var req UpsertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, model.Err(400, "参数错误: "+err.Error()))
		return
	}

	// 验证证书与私钥匹配
	if err := cert.ValidateCertKey(req.CertPEM, req.KeyPEM); err != nil {
		c.JSON(400, model.Err(400, err.Error()))
		return
	}

	// 提取元数据
	notBefore, notAfter, sans, err := cert.ExtractMeta(req.CertPEM)
	if err != nil {
		c.JSON(400, model.Err(400, "证书解析失败: "+err.Error()))
		return
	}
	fp, err := cert.FingerprintPEM([]byte(req.CertPEM))
	if err != nil {
		c.JSON(400, model.Err(400, "指纹计算失败"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 版本递增
	var version int64 = 1
	var createdAt = time.Now()
	if existing, _ := h.etcd.GetMeta(ctx, req.Domain); existing != nil {
		version = existing.Version + 1
		createdAt = existing.CreatedAt
	}

	bundle := &model.CertBundle{
		Meta: &model.CertMeta{
			Domain:      req.Domain,
			Version:     version,
			Fingerprint: fp,
			NotBefore:   notBefore,
			NotAfter:    notAfter,
			SANDomains:  sans,
			HasChain:    req.ChainPEM != "",
			Description: req.Description,
			CreatedAt:   createdAt,
			UpdatedAt:   time.Now(),
		},
		CertPEM:  req.CertPEM,
		KeyPEM:   req.KeyPEM,
		ChainPEM: req.ChainPEM,
	}

	if err := h.etcd.PutCert(ctx, bundle); err != nil {
		c.JSON(500, model.Err(500, "写入失败: "+err.Error()))
		return
	}

	h.logger.Info("证书已上传",
		zap.String("domain", req.Domain),
		zap.Int64("version", version),
		zap.String("ip", c.ClientIP()),
	)
	c.JSON(200, model.OK(gin.H{
		"domain":      req.Domain,
		"version":     version,
		"fingerprint": fp,
		"not_after":   notAfter,
	}))
}

// DELETE /api/v1/certs/:domain
func (h *Handler) DeleteCert(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	if err := h.etcd.DeleteCert(ctx, c.Param("domain")); err != nil {
		c.JSON(500, model.Err(500, err.Error()))
		return
	}
	h.logger.Info("证书已删除", zap.String("domain", c.Param("domain")))
	c.JSON(200, model.OK(nil))
}

// GET /api/v1/agents
func (h *Handler) ListAgents(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	list, err := h.etcd.ListStatus(ctx)
	if err != nil {
		c.JSON(500, model.Err(500, err.Error()))
		return
	}
	c.JSON(200, model.OK(list))
}

// GET /api/v1/health
func (h *Handler) Health(c *gin.Context) {
	c.JSON(200, model.OK(gin.H{"status": "ok", "time": time.Now()}))
}
