package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"

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
	cookieName    string    `required:"true" split_words:"true"`
	tokenSecret   string    `required:"true" split_words:"true"`
	sites         AuthSites `required:"true" split_words:"true"`
	managementAPI string    `required:"true" split_words:"true"`

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
	cookie, err := r.Cookie(p.cookieName)
	if err != nil {
		p.log.Info("no jwt exists, calling management api")
		return p.managementAPI, nil
	}

	_, err = jwt.ParseWithClaims(cookie.Value, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(p.tokenSecret), nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		p.log.Info("jwt has expired")
		return p.managementAPI, nil
	} else if err != nil {
		return "", err
	}

	result, ok := p.sites[p.claim.Level]
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

	secret, err := base64.StdEncoding.DecodeString(p.tokenSecret)
	if err != nil {
		return p, fmt.Errorf("unable to decode Proxy TokenSecret: %w", err)
	}
	p.tokenSecret = string(secret)

	return p, err
}
