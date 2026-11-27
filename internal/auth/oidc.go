package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const providerTimeout = 10 * time.Second

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Origin       string
}

type oidcProvider struct {
	issuer   string
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

func discoverOIDC(ctx context.Context, cfg OIDCConfig, client *http.Client) (*oidcProvider, error) {
	issuer, err := httpsURL(cfg.Issuer)
	if err != nil || issuer.RawQuery != "" || issuer.ForceQuery {
		return nil, errors.New("OIDC issuer must be an HTTPS URL without query or fragment")
	}
	origin, err := httpsURL(cfg.Origin)
	if err != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery {
		return nil, errors.New("public origin must be https://host[:port] without a trailing slash")
	}
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("OIDC client ID and client secret are required")
	}

	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), providerTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, errors.New("OIDC discovery failed; check the issuer URL, TLS trust and connectivity")
	}
	var metadata struct {
		JWKSURL   string   `json:"jwks_uri"`
		AuthModes []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, errors.New("invalid OIDC provider metadata")
	}
	endpoint := provider.Endpoint()
	for _, address := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKSURL} {
		if _, err := httpsURL(address); err != nil {
			return nil, errors.New("OIDC authorization, token and JWKS endpoints must use HTTPS")
		}
	}
	switch {
	case len(metadata.AuthModes) == 0 || slices.Contains(metadata.AuthModes, "client_secret_basic"):
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case slices.Contains(metadata.AuthModes, "client_secret_post"):
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	default:
		return nil, errors.New("OIDC provider does not support client_secret_basic or client_secret_post")
	}

	return &oidcProvider{
		issuer: cfg.Issuer,
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			Endpoint: endpoint, RedirectURL: cfg.Origin + loginCallbackPath,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		client:   client,
	}, nil
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

func (p *oidcProvider) authenticate(ctx context.Context, code string, attempt loginAttempt) (string, error) {
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, p.client), providerTimeout)
	defer cancel()
	if code == "" || attempt.codeVerifier == "" || attempt.nonce == "" {
		return "", errors.New("incomplete login attempt")
	}
	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(attempt.codeVerifier))
	if err != nil {
		return "", errors.New("OIDC code exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("OIDC token response is missing an ID token")
	}
	id, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return "", errors.New("OIDC ID token verification failed")
	}
	var claims struct {
		AuthorizedParty *string `json:"azp"`
	}
	if err := id.Claims(&claims); err != nil || id.Issuer != p.issuer ||
		id.IssuedAt.IsZero() || len(id.Audience) != 1 || id.Audience[0] != p.oauth.ClientID ||
		(claims.AuthorizedParty != nil && *claims.AuthorizedParty != p.oauth.ClientID) ||
		strings.TrimSpace(id.Subject) == "" || len(id.Subject) > 255 ||
		subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(attempt.nonce)) != 1 {
		return "", errors.New("OIDC identity claims did not match this login")
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return "", errors.New("OIDC access token hash did not match")
	}
	digest := sha256.Sum256([]byte(id.Issuer + "\x00" + id.Subject))
	return fmt.Sprintf("oidc:%x", digest), nil
}
