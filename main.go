package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
	_ caddy.Validator             = (*Proxy)(nil)
	_ caddyhttp.MiddlewareHandler = (*Proxy)(nil)
	_ caddyfile.Unmarshaler       = (*Proxy)(nil)
)

func init() {
	caddy.RegisterModule(Proxy{})
	httpcaddyfile.RegisterHandlerDirective("dynamic_proxy", parseCaddyfile)
}

type ProxyAuth struct {
	ManagementAPI  string `required:"true" split_words:"true"`
	CookieName     string `required:"true" split_words:"true"`
	TokenSecret    string `required:"true" split_words:"true"`
	SiteOne        string `required:"true" split_words:"true"`
	SiteOneLevel   string `required:"true" split_words:"true"`
	SiteTwo        string `required:"true" split_words:"true"`
	SiteTwoLevel   string `required:"true" split_words:"true"`
	SiteThree      string `required:"true" split_words:"true"`
	SiteThreeLevel string `required:"true" split_words:"true"`
}

type ProxyClaim struct {
	Level string `json:"level"`
	jwt.RegisteredClaims
}

type Proxy struct {
	auth  ProxyAuth
	claim ProxyClaim
	sites map[string]string

	log *zap.Logger
}

func (Proxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dynamic_proxy",
		New: func() caddy.Module { return new(Proxy) },
	}
}

// Provision implements caddy.Provisioner.
func (p *Proxy) Provision(ctx caddy.Context) error {
	p.log = ctx.Logger(p)

	if err := envconfig.Process("auth", &p.auth); err != nil {
		return err
	}

	secret, err := base64.StdEncoding.DecodeString(p.auth.TokenSecret)
	if err != nil {
		return fmt.Errorf("unable to decode Proxy TokenSecret: %w", err)
	}
	p.auth.TokenSecret = string(secret)

	p.sites = make(map[string]string)
	p.sites[p.auth.SiteOneLevel] = p.auth.SiteOne
	p.sites[p.auth.SiteTwoLevel] = p.auth.SiteTwo
	p.sites[p.auth.SiteThreeLevel] = p.auth.SiteThree

	return nil
}

// Validate implements caddy.Validator.
func (p Proxy) Validate() error {
	if p.auth.CookieName == "" {
		return fmt.Errorf("missing `AUTH_COOKIE_NAME`")
	}

	if p.auth.TokenSecret == "" {
		return fmt.Errorf("missing `AUTH_TOKEN_SECRET`")
	}

	if len(p.sites) == 0 {
		return fmt.Errorf("missing `AUTH_URLS`")
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *Proxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()

	for d.NextBlock(0) {
		switch d.Val() {
		default:
			return fmt.Errorf("unknown option `%s` in `dynamic_proxy`", d.Val())
		}
	}

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
	p.log.Info("setting proxy to " + to)

	return next.ServeHTTP(w, r)
}

func (p Proxy) authRedirect(r *http.Request) (string, error) {
	// if no cookie, redirect to get new cookie
	cookie, err := r.Cookie(p.auth.CookieName)
	if err != nil {
		p.log.Info("no jwt exists, calling management api")
		return p.auth.ManagementAPI, nil
	}

	_, err = jwt.ParseWithClaims(cookie.Value, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(p.auth.TokenSecret), nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		p.log.Info("jwt has expired")
		return p.auth.ManagementAPI, nil
	} else if err != nil {
		return "", err
	}

	result, ok := p.sites[p.claim.Level]
	if !ok {
		return "", fmt.Errorf("unknown auth level: %v", p.claim.Level)
	}

	return result, nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p Proxy
	err := p.UnmarshalCaddyfile(h.Dispenser)
	return p, err
}
