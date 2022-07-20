package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func Test_AuthProxy(t *testing.T) {
	cookieName := "_test"
	tokenSecret := "secret"
	managementAPI := "management_api"
	authURLs := map[string]string{"good": "good url"}
	validTime := time.Now().AddDate(0, 0, 1)
	expiredTime := time.Now().AddDate(0, 0, -1)

	tests := []struct {
		name    string
		Cookie  *http.Cookie
		wantErr bool
		want    string
	}{
		{
			name:    "no cookie",
			Cookie:  nil,
			wantErr: false,
			want:    managementAPI,
		},
		{
			name:    "invalid cookie",
			Cookie:  makeTestJWTCookie(cookieName, "bad", "good", validTime),
			wantErr: true,
			want:    "signature is invalid",
		},
		{
			name:    "expired cookie",
			Cookie:  makeTestJWTCookie(cookieName, tokenSecret, "good", expiredTime),
			wantErr: false,
			want:    managementAPI,
		},
		{
			name:    "invalid level",
			Cookie:  makeTestJWTCookie(cookieName, tokenSecret, "bad", validTime),
			wantErr: true,
			want:    "unknown auth level",
		},
		{
			name:    "valid",
			Cookie:  makeTestJWTCookie(cookieName, tokenSecret, "good", validTime),
			wantErr: false,
			want:    authURLs["good"],
		},
	}

	assert := assert.New(t)
	proxy := Proxy{
		ManagementAPI: managementAPI,
		auth: ProxyAuth{
			cookieName,
			tokenSecret,
			authURLs,
		},
		log: zap.L(),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.Cookie != nil {
				r.AddCookie(tc.Cookie)
			}

			to, err := proxy.authRedirect(r)
			if tc.wantErr {
				assert.NotNil(err)
				assert.Contains(err.Error(), tc.want)
			} else {
				assert.Nil(err)
				assert.Equal(tc.want, to)
			}
		})
	}
}

func makeTestJWTCookie(name, secret, level string, expires time.Time) *http.Cookie {
	claim := ProxyClaim{
		Level: level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(expires.AddDate(0, 0, -1)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, _ := token.SignedString([]byte(secret))

	return &http.Cookie{
		Name:  name,
		Value: tokenString,
	}
}
