package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"go.uber.org/zap"
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
	CookieName    string    `required:"true" split_words:"true"`
	TokenSecret   string    `required:"true" split_words:"true"`
	Sites         AuthSites `required:"true" split_words:"true"`
	ManagementAPI string    `required:"true" split_words:"true"`

	claim ProxyClaim  `ignored:"true"`
	log   *zap.Logger `ignored:"true"`
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

	to, err := p.authRedirect(r)
	if err != nil {
		return err
	}
	caddyhttp.SetVar(r.Context(), "upstream", to)
	p.log.Info("setting upstream to " + to)

	return next.ServeHTTP(w, r)
}

func (p Proxy) authRedirect(r *http.Request) (string, error) {
	// if no cookie, redirect to get new cookie
	cookie, err := r.Cookie(p.CookieName)
	if err != nil {
		p.log.Info("no jwt exists, calling management api")

		returnTo := url.QueryEscape(os.Getenv("HOST") + r.URL.Path)
		caddyhttp.SetVar(r.Context(), "returnTo", returnTo)
		p.log.Info("setting returnTo to " + returnTo)

		return p.ManagementAPI, nil
	}

	_, err = jwt.ParseWithClaims(cookie.Value, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(p.TokenSecret), nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		p.log.Info("jwt has expired")
		return p.ManagementAPI, nil
	} else if err != nil {
		return "", fmt.Errorf("authRedirect failed to parse token: %w", err)
	}

	result, ok := p.Sites[p.claim.Level]
	if !ok {
		return "", fmt.Errorf("unknown auth level: %v", p.claim.Level)
	}

	return result, nil
}

func newDynamicProxy(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return newProxy()
}

func newProxy() (Proxy, error) {
	var p Proxy
	if err := envconfig.Process("", &p); err != nil {
		return p, err
	}

	secret, err := base64.StdEncoding.DecodeString(p.TokenSecret)
	if err != nil {
		return p, fmt.Errorf("unable to decode Proxy TokenSecret: %w", err)
	}
	p.TokenSecret = string(secret)

	return p, err
}
