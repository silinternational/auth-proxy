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
	assert := assert.New(t)
	cookieName := "_test"
	tokenSecret := []byte("secret")
	managementAPI := "management_api"
	authURLs := AuthSites{"good": "good url"}
	validTime := time.Now().AddDate(0, 0, 1)
	expiredTime := time.Now().AddDate(0, 0, -1)
	proxy := Proxy{
		CookieName: cookieName,
		Secret:     tokenSecret,
		Sites:      authURLs,
		log:        zap.L(),
	}

	tests := []struct {
		name    string
		cookie  *http.Cookie
		wantErr bool
		want    string
	}{
		{
			name:    "no cookie",
			cookie:  nil,
			wantErr: false,
			want:    managementAPI,
		},
		{
			name:    "invalid cookie",
			cookie:  makeTestJWTCookie(cookieName, []byte("bad"), "good", validTime),
			wantErr: true,
			want:    "signature is invalid",
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
			want:    "unknown auth level",
		},
		{
			name:    "valid",
			cookie:  makeTestJWTCookie(cookieName, tokenSecret, "good", validTime),
			wantErr: false,
			want:    authURLs["good"],
		},
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
				assert.ErrorContains(err, tc.want)
			} else {
				assert.NoError(err)
				assert.Equal(tc.want, to)
			}
		})
	}
}

func makeTestJWTCookie(name string, secret []byte, level string, expires time.Time) *http.Cookie {
	claim := ProxyClaim{
		Level: level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(expires.AddDate(0, 0, -1)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, _ := token.SignedString(secret)

	return &http.Cookie{
		Name:  name,
		Value: tokenString,
	}
}
