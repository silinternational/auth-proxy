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
		cookie  *http.Cookie
		want    string
		wantErr bool
		err     string
	}{
		{
			name:    "no cookie",
			cookie:  nil,
			wantErr: false,
			want:    managementAPI,
		},
		{
			name:    "invalid cookie",
			cookie:  makeTestJWTCookie(cookieName, "bad", "good", validTime),
			wantErr: true,
			err:     "signature is invalid",
		},
		{
			name:    "expired cookie",
			cookie:  makeTestJWTCookie(cookieName, tokenSecret, "good", expiredTime),
			wantErr: false,
			want:    managementAPI,
		},
		{
			name:    "invalid level",
			cookie:  makeTestJWTCookie(cookieName, tokenSecret, "bad", validTime),
			wantErr: true,
			err:     "unknown auth level",
		},
		{
			name:    "valid",
			cookie:  makeTestJWTCookie(cookieName, tokenSecret, "good", validTime),
			wantErr: false,
			want:    authURLs["good"],
		},
	}

	assert := assert.New(t)
	proxy := Proxy{
		auth: ProxyAuth{
			CookieName:  cookieName,
			TokenSecret: tokenSecret,
		},
		sites: authURLs,
		log:   zap.L(),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}

			to, err := proxy.authRedirect(r)
			if tc.wantErr {
				assert.ErrorContains(err, tc.err)
			} else {
				assert.NoError(err)
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
