package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

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
	CookieName  string            `required:"true" split_words:"true"`
	TokenSecret string            `required:"true" split_words:"true"`
	URLs        map[string]string `required:"true"`
}

type ProxyClaim struct {
	Level string `json:"level"`
	jwt.RegisteredClaims
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
	var err error
	p.log = ctx.Logger(p)
	if p.auth, err = newProxyAuth(); err != nil {
		return err
	}

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
	cookie, err := r.Cookie(p.auth.CookieName)
	if err != nil {
		return p.ManagementAPI, nil
	}

	_, err = jwt.ParseWithClaims(cookie.Value, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(p.auth.TokenSecret), nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return p.ManagementAPI, nil
	} else if err != nil {
		return "", err
	}

	result, ok := p.auth.URLs[p.claim.Level]
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

func newProxyAuth() (ProxyAuth, error) {
	var auth ProxyAuth
	if err := envconfig.Process("auth", &auth); err != nil {
		return auth, err
	}

	for i, u := range auth.URLs {
		u, err := url.QueryUnescape(u)
		if err != nil {
			return auth, err
		}

		parsed, err := url.Parse("http://" + u)
		if err != nil {
			return auth, err
		}

		if parsed.Port() == "" {
			u = parsed.Host + ":80" + parsed.Path
		}

		auth.URLs[i] = u
	}

	secret, err := base64.StdEncoding.DecodeString(auth.TokenSecret)
	if err != nil {
		return auth, fmt.Errorf("unable to decode Proxy TokenSecret: %w", err)
	}

	auth.TokenSecret = string(secret)
	return auth, nil
}
