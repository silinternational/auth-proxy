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

func Test_AuthSiteDecode(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		name    string
		value   string
		wantErr bool
		want    AuthSite
		err     string
	}{
		{
			name:    "nothing",
			value:   "",
			wantErr: true,
			err:     "cannot decode empty string",
		},
		{
			name:    "no protocol",
			value:   "noprotocol:9000",
			wantErr: false,
			want:    AuthSite{"noprotocol:9000", ""},
		},
		{
			name:    "no port",
			value:   "noport",
			wantErr: false,
			want:    AuthSite{"noport:80", ""},
		},
		{
			name:    "ftp",
			value:   "ftp://ftp:9000",
			wantErr: false,
			want:    AuthSite{"ftp:9000", ""},
		},
		{
			name:    "http",
			value:   "http://http:9000",
			wantErr: false,
			want:    AuthSite{"http:9000", ""},
		},
		{
			name:    "with path",
			value:   "http://withpath:9000/test/path",
			wantErr: false,
			want:    AuthSite{"withpath:9000", "/test/path"},
		},
		{
			name:    "http.com",
			value:   "http://http.com:9000",
			wantErr: false,
			want:    AuthSite{"http.com:9000", ""},
		},
	}

	var got AuthSite
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := got.Decode(tc.value)
			if tc.wantErr {
				assert.ErrorContains(err, tc.err)
			} else {
				assert.NoError(err)
				assert.Equal(tc.want, got)
			}
		})
	}
}

func Test_AuthProxy(t *testing.T) {
	cookieName := "_test"
	tokenSecret := "secret"
	managementAPI := AuthSite{"management", "api"}
	authURLs := map[string]AuthSite{"good": {"good", "url"}}
	validTime := time.Now().AddDate(0, 0, 1)
	expiredTime := time.Now().AddDate(0, 0, -1)

	tests := []struct {
		name    string
		Cookie  *http.Cookie
		wantErr bool
		want    AuthSite
		err     string
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
			err:     "signature is invalid",
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
			err:     "unknown auth level",
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
		auth: ProxyAuth{
			CookieName:  cookieName,
			TokenSecret: tokenSecret,
			Sites:       authURLs,
		},
		api: managementAPI,
		log: zap.L(),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.Cookie != nil {
				r.AddCookie(tc.Cookie)
			}

			got, err := proxy.authRedirect(r)
			if tc.wantErr {
				assert.ErrorContains(err, tc.err)
			} else {
				assert.NoError(err)
				assert.Equal(tc.want, got)
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
