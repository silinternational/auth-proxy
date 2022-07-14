package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"

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

type Proxy struct {
	ManagementAPI string `json:"management_api,omitempty"`

	auth struct {
		CookieName  string            `required:"true" split_words:"true"`
		TokenSecret string            `required:"true" split_words:"true"`
		URLs        map[string]string `required:"true"`
	}
	claim struct {
		Level string `json:"level"`
		jwt.StandardClaims
	}

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

	return envconfig.Process("auth", &p.auth)
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

	// check cookie, if none exist with name
	cookie, err := r.Cookie(p.auth.CookieName)
	if err != nil {
		return err
	}

	// if cookie expired return error
	// p.log.Info(cookie.Expires.String())
	// p.log.Info(time.Now().String())
	// if time.Now().After(cookie.Expires) {
	// 	return fmt.Errorf("jwt expired")
	// }

	secret, err := base64.StdEncoding.DecodeString(p.auth.TokenSecret)
	if err != nil {
		return fmt.Errorf("unable to decode ProxyTokenSecret: %w", err)
	}

	_, err = jwt.ParseWithClaims(cookie.Value, &p.claim, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})
	if err != nil {
		return err
	}

	url, ok := p.auth.URLs[p.claim.Level]
	if !ok {
		return fmt.Errorf("unknown auth level: %v", p.claim.Level)
	}

	caddyhttp.SetVar(r.Context(), "upstream", url)
	p.log.Info("setting upstream to " + url)

	return next.ServeHTTP(w, r)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p Proxy
	err := p.UnmarshalCaddyfile(h.Dispenser)
	return p, err
}
