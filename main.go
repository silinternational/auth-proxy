package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt"
	"github.com/kelseyhightower/envconfig"
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
	CookieName  string            `required:"true" split_words:"true"`
	TokenSecret string            `required:"true" split_words:"true"`
	URLs        map[string]string `required:"true"`
}

type ProxyClaim struct {
	Level string `json:"level"`
	jwt.StandardClaims
}

type Proxy struct {
	ManagementAPI string `json:"management_api,omitempty"`

	auth  ProxyAuth
	claim ProxyClaim

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
		return fmt.Errorf("unable to decode ProxyTokenSecret: %w", err)
	}

	p.auth.TokenSecret = string(secret)
	return nil
}

// Validate implements caddy.Validator.
func (p Proxy) Validate() error {
	if p.ManagementAPI == "" {
		return fmt.Errorf("missing `management_api` in `dynamic_proxy`")
	}

	if p.auth.CookieName == "" {
		return fmt.Errorf("missing `AUTH_COOKIE_NAME`")
	}

	if p.auth.TokenSecret == "" {
		return fmt.Errorf("missing `AUTH_TOKEN_SECRET`")
	}

	if len(p.auth.URLs) == 0 {
		return fmt.Errorf("missing `AUTH_URLS`")
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *Proxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()

	for d.NextBlock(0) {
		switch d.Val() {
		case "management_api":
			if !d.AllArgs(&p.ManagementAPI) {
				return d.ArgErr()
			}
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

	if err := p.authRedirect(r); err != nil {
		return err
	}

	return next.ServeHTTP(w, r)
}

func (p Proxy) authRedirect(r *http.Request) error {
	// if no cookie, redirect to get new cookie
	cookie, err := r.Cookie(p.auth.CookieName)
	if err != nil {
		return p.setVar(r, "upstream", p.ManagementAPI)
	}

	_, err = jwt.ParseWithClaims(cookie.Value, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(p.auth.TokenSecret), nil
	})
	if err != nil {
		return err
	}

	// if cookie expired at is past, redirect to get new cookie
	if p.claim.ExpiresAt < time.Now().Unix() {
		return p.setVar(r, "upstream", p.ManagementAPI)
	}

	url, ok := p.auth.URLs[p.claim.Level]
	if !ok {
		return fmt.Errorf("unknown auth level: %v", p.claim.Level)
	}

	return p.setVar(r, "upstream", url)
}

func (p Proxy) setVar(r *http.Request, name, value string) error {
	caddyhttp.SetVar(r.Context(), name, value)
	p.log.Info("setting " + name + " to " + value)
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p Proxy
	err := p.UnmarshalCaddyfile(h.Dispenser)
	return p, err
}
