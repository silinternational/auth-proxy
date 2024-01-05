package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
)

const (
	CaddyVarUpstream    = "upstream"
	CaddyVarRedirectURL = "redirect_url"
)

// Interface guards
var (
	_ caddy.Provisioner           = (*Proxy)(nil)
	_ caddyhttp.MiddlewareHandler = (*Proxy)(nil)
)

func init() {
	caddy.RegisterModule(Proxy{})
	httpcaddyfile.RegisterHandlerDirective("dynamic_proxy", newDynamicProxy)
}

type ProxyClaim struct {
	Level string `json:"level"`
	jwt.RegisteredClaims
}

type Proxy struct {
	Host          string    `required:"true"`
	TokenSecret   string    `required:"true" split_words:"true"`
	Sites         AuthSites `required:"true" split_words:"true"`
	ManagementAPI string    `required:"true" split_words:"true"`

	// optional params
	CookieName    string `default:"_auth_proxy" split_words:"true"`
	ReturnToParam string `default:"returnTo" split_words:"true"`
	TokenParam    string `default:"token" split_words:"true"`
	TokenPath     string `default:"/auth/token" split_words:"true"`

	// Secret is the binary token secret. Must be exported to be valid after being passed back from Caddy.
	Secret []byte `ignored:"true"`

	claim ProxyClaim  `ignored:"true"`
	log   *zap.Logger `ignored:"true"`
}

type Error struct {
	// Message contains a message that is safe for display to the end user
	Message string

	// Status is the http status code for the response
	Status int

	// err contains the original error message, not necessarily safe for display to the end user
	err error
}

func (e *Error) Error() string {
	return e.err.Error()
}

func (Proxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dynamic_proxy",
		New: func() caddy.Module { return new(Proxy) },
	}
}

func (p *Proxy) Provision(ctx caddy.Context) error {
	p.log = ctx.Logger(p)
	return nil
}

func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// setup the robots.txt options
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if r.URL.Path == "/robots.txt" {
		w.Write([]byte("User-agent: * Disallow: /"))
		return nil
	}

	if r.URL.Path == "/status" {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	if err := p.authRedirect(w, r); err != nil {
		w.WriteHeader(err.Status)
		_, writeErr := w.Write([]byte(err.Message))
		if writeErr != nil {
			p.log.Error("couldn't write to response buffer: %s" + writeErr.Error())
		}
		p.log.Error(err.Message, zap.Int("status", err.Status), zap.String("error", err.Error()))
		return err
	}

	return next.ServeHTTP(w, r)
}

func (p Proxy) authRedirect(w http.ResponseWriter, r *http.Request) *Error {
	token := p.getToken(r)

	if token == "" {
		p.log.Info("no token found, calling management api")
		p.setVar(r, CaddyVarRedirectURL, p.ManagementAPI+p.TokenPath+"?returnTo="+url.QueryEscape(p.Host+r.URL.Path))
		return nil
	}

	_, err := jwt.ParseWithClaims(token, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := &Error{
				err:     fmt.Errorf("unexpected signing method: %v", token.Header["alg"]),
				Message: "error: invalid access token",
				Status:  http.StatusBadRequest,
			}
			return nil, err
		}

		return p.Secret, nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		p.log.Info("jwt has expired, calling management api")
		p.setVar(r, CaddyVarRedirectURL, p.ManagementAPI+p.TokenPath+"?returnTo="+url.QueryEscape(p.Host+r.URL.Path))
		return nil
	} else if err != nil {
		return &Error{
			err:     fmt.Errorf("authRedirect failed to parse token: %w", err),
			Message: "error: corrupted access token",
			Status:  http.StatusBadRequest,
		}
	}

	ck := http.Cookie{
		Name:    p.CookieName,
		Value:   token,
		Expires: p.claim.ExpiresAt.Time,
		Path:    "/",
	}
	http.SetCookie(w, &ck)

	upstream, ok := p.Sites[p.claim.Level]
	if !ok {
		return &Error{
			err:     fmt.Errorf("auth level '%v' not in sites: %v", p.claim.Level, p.Sites),
			Message: "error: unrecognized access level",
			Status:  http.StatusBadRequest,
		}
	}

	returnTo := r.URL.Query().Get(p.ReturnToParam)
	if returnTo != "" && p.isTrusted(returnTo) {
		p.setVar(r, CaddyVarRedirectURL, returnTo)
		return nil
	}

	p.setVar(r, CaddyVarUpstream, upstream)
	return nil
}

func (p *Proxy) isTrusted(returnTo string) bool {
	if strings.HasPrefix(returnTo, p.ManagementAPI) {
		return true
	}
	if strings.HasPrefix(returnTo, p.Host) {
		return true
	}
	return false
}

func (p Proxy) setVar(r *http.Request, name, value string) {
	caddyhttp.SetVar(r.Context(), name, value)
	p.log.Info("setting " + name + " to " + value)
}

func newDynamicProxy(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return newProxy()
}

func newProxy() (Proxy, error) {
	var p Proxy
	if err := envconfig.Process("", &p); err != nil {
		return p, err
	}

	var err error
	p.Secret, err = base64.StdEncoding.DecodeString(p.TokenSecret)
	if err != nil {
		return p, fmt.Errorf("unable to decode Proxy TokenSecret: %w", err)
	}
	return p, nil
}

// getToken returns a token found in either a cookie or the query string. If found in the query string, set a Caddy
// variable to force a redirect to clear it from the query string.
func (p Proxy) getToken(r *http.Request) string {
	if token := r.URL.Query().Get(p.TokenParam); token != "" {
		// if we got the token from the query string, set a URL for the Caddyfile to redirect without it
		u := r.URL
		q := u.Query()
		q.Del(p.TokenParam)
		u.RawQuery = q.Encode()

		p.setVar(r, CaddyVarRedirectURL, u.String())
		return token
	}

	if cookie, err := r.Cookie(p.CookieName); err == nil {
		return cookie.Value
	}
	return ""
}
