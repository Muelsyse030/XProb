package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const sessionTTL = 8 * time.Hour

type SessionRevoker interface {
	RevokeSession(ctx context.Context, tokenHash [32]byte) error
}

type SessionStore interface {
	SessionReader
	SessionWriter
	SessionRevoker
}

type Login struct {
	provider *oidcProvider
	attempts *memoryLoginAttempts
	sessions SessionStore
	origin   string
}

func NewLogin(ctx context.Context, cfg OIDCConfig, sessions SessionStore) (*Login, error) {
	client := &http.Client{
		Timeout: providerTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return newLogin(ctx, cfg, sessions, client)
}

func newLogin(ctx context.Context, cfg OIDCConfig, sessions SessionStore, client *http.Client) (*Login, error) {
	provider, err := discoverOIDC(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	return &Login{provider: provider, attempts: newMemoryLoginAttempts(), sessions: sessions, origin: cfg.Origin}, nil
}

func (l *Login) RegisterRoutes(router *gin.Engine) {
	cfg := loginConfig{
		authorizationEndpoint: l.provider.oauth.Endpoint.AuthURL,
		clientID:              l.provider.oauth.ClientID,
		redirectURI:           l.provider.oauth.RedirectURL,
	}
	router.GET("/auth/login", startLoginHandler(l.attempts, cfg, time.Now))
	router.GET(loginCallbackPath, loginCallbackHandler(l.attempts, l.provider.authenticate, l.sessions, time.Now))
	router.GET("/auth/me", noStore, RequireSession(l.sessions), func(c *gin.Context) {
		userID, _ := SessionUserID(c)
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})
	router.POST("/auth/logout", noStore, RequireSameOrigin(l.origin), logoutHandler(l.sessions))
}

func noStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Next()
}
