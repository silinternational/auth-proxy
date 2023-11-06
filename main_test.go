package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func Test_AuthProxy(t *testing.T) {
	const managementAPI = "http://management_api.example.com"
	const tokenPath = "/auth/token"

	assert := assert.New(t)
	cookieName := "_test"
	tokenSecret := []byte("secret")
	authURLs := AuthSites{"good": "good url"}
	validTime := time.Now().AddDate(0, 0, 1)
	expiredTime := time.Now().AddDate(0, 0, -1)
	proxy := Proxy{
		CookieName:    cookieName,
		Secret:        tokenSecret,
		Sites:         authURLs,
		log:           zap.L(),
		ManagementAPI: managementAPI,
		TokenPath:     tokenPath,
	}

	redirectURL := managementAPI + tokenPath + "?returnTo=%2F"
	upstream := authURLs["good"]

	tests := []struct {
		name            string
		cookie          *http.Cookie
		wantErr         string
		wantRedirectURL *string
		wantUpstream    *string
	}{
		{
			name:            "no cookie",
			cookie:          nil,
			wantErr:         "",
			wantRedirectURL: &redirectURL,
		},
		{
			name:    "invalid cookie",
			cookie:  makeTestJWTCookie(cookieName, makeTestJWT([]byte("bad"), "good", validTime)),
			wantErr: "signature is invalid",
		},
		{
			name:            "expired cookie",
			cookie:          makeTestJWTCookie(cookieName, makeTestJWT(tokenSecret, "good", expiredTime)),
			wantErr:         "",
			wantRedirectURL: &redirectURL,
		},
		{
			name:    "invalid level",
			cookie:  makeTestJWTCookie(cookieName, makeTestJWT(tokenSecret, "bad", validTime)),
			wantErr: "not in sites",
		},
		{
			name:         "valid",
			cookie:       makeTestJWTCookie(cookieName, makeTestJWT(tokenSecret, "good", validTime)),
			wantErr:      "",
			wantUpstream: &upstream,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			ctx := context.WithValue(r.Context(), caddy.CtxKey("vars"), map[string]any{})
			r = r.WithContext(ctx)

			var w httptest.ResponseRecorder
			err := proxy.authRedirect(&w, r)

			if tc.wantErr != "" {
				assert.ErrorContains(err, tc.wantErr)
				return
			}
			assert.Nil(err)

			if tc.wantUpstream != nil {
				assert.Equal(*tc.wantUpstream, caddyhttp.GetVar(r.Context(), CaddyVarUpstream))
			}
			if tc.wantRedirectURL != nil {
				assert.Equal(*tc.wantRedirectURL, caddyhttp.GetVar(r.Context(), CaddyVarRedirectURL))
			}
		})
	}
}

func makeTestJWTCookie(name, token string) *http.Cookie {
	return &http.Cookie{
		Name:  name,
		Value: token,
	}
}

func makeTestJWT(secret []byte, level string, expires time.Time) string {
	claim := ProxyClaim{
		Level: level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(expires.AddDate(0, 0, -1)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, _ := token.SignedString(secret)

	return tokenString
}
