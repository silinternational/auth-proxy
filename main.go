package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// CookieFlag is a query string flag to indicate a cookie has been requested. It remains set until the requested
// cookie has been verified. This is required to support user agents that do not allow cookies.
const CookieFlag = "cf"

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
	Level   string `json:"level"`
	IsValid bool
	jwt.RegisteredClaims
}

type Proxy struct {
	DefaultSite   string    `required:"true" split_words:"true"`
	Host          string    `required:"true"`
	TokenSecret   string    `required:"true" split_words:"true"`
	Sites         AuthSites `required:"true" split_words:"true"`
	ManagementAPI string    `required:"true" split_words:"true"`

	// optional params
	CookieName       string   `split_words:"true" default:"_auth_proxy"`
	ReturnToParam    string   `split_words:"true" default:"returnTo"`
	RobotsTxtDisable bool     `split_words:"true" default:"false"`
	TokenParam       string   `split_words:"true" default:"token"`
	TokenPath        string   `split_words:"true" default:"/auth/token"`
	TrustedBots      []string `split_words:"true" default:"googlebot"`

	// Secret is the binary token secret. Must be exported to be valid after being passed back from Caddy.
	Secret []byte `ignored:"true"`

	log *zap.Logger `ignored:"true"`
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
	if !p.RobotsTxtDisable {
		// setup the robots.txt options
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		if r.URL.Path == "/robots.txt" {
			_, err := w.Write([]byte("User-agent: * Disallow: /"))
			if err != nil {
				return fmt.Errorf("failed to write robots.txt: %w", err)
			}
			return nil
		}
	}

	if r.URL.Path == "/status" {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	if err := p.handleRequest(w, r); err != nil {
		var proxyError *Error
		if errors.As(err, &proxyError) {
			w.WriteHeader(proxyError.Status)
			_, writeErr := w.Write([]byte(proxyError.Message))
			if writeErr != nil {
				p.log.Error("couldn't write to response buffer: %s" + writeErr.Error())
			}
			p.log.Error(proxyError.Message, zap.Int("status", proxyError.Status), zap.String("error", err.Error()))
		}
		return err
	}

	return next.ServeHTTP(w, r)
}

func (p Proxy) handleRequest(w http.ResponseWriter, r *http.Request) error {
	if p.isTrustedBot(r) {
		upstream := p.DefaultSite
		p.setVar(r, CaddyVarUpstream, upstream)
		p.log.Info("trusted bot", zap.String("user-agent", r.UserAgent()), zap.String("upstream", upstream))
		return nil
	}

	queryToken := p.getTokenFromQueryString(r)
	queryClaim := p.getClaimFromToken(queryToken)
	cookieToken := p.getTokenFromCookie(r)
	cookieClaim := p.getClaimFromToken(cookieToken)

	var token string
	var claim ProxyClaim

	if queryClaim.IsValid {
		token = queryToken
		claim = queryClaim
	} else if cookieClaim.IsValid {
		token = cookieToken
		claim = cookieClaim
	} else {
		p.log.Info("no valid token found, calling management API", zap.String("URL", p.ManagementAPI+p.TokenPath))
		return p.getNewToken(w, r)
	}

	// if a cookie hasn't been requested, try to set one
	flag := p.getFlag(r)
	if !flag {
		// set a cookie if we don't have a valid one OR if we need to replace it with a new one
		if !cookieClaim.IsValid || claimsAreValidAndDifferent(queryClaim, cookieClaim) {
			p.setCookie(w, token, claim.ExpiresAt.Time)
			p.setFlag(r)
			return nil
		}
	}

	// if the cookie is valid, it's safe to clear the query string
	if cookieClaim.IsValid {
		redirect := false
		if queryToken != "" {
			p.clearQueryToken(r)
			redirect = true
		}
		if flag {
			p.clearFlag(r)
			redirect = true
		}
		if redirect {
			return nil
		}
	}

	returnTo := r.URL.Query().Get(p.ReturnToParam)
	if returnTo != "" && p.isTrusted(returnTo) {
		p.setVar(r, CaddyVarRedirectURL, returnTo)
		return nil
	}

	upstream := p.getSite(claim.Level)

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
	p.log.Debug("setting " + name + " to " + value)
}

func newDynamicProxy(_ httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
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

	for i := range p.TrustedBots {
		p.TrustedBots[i] = strings.ToLower(p.TrustedBots[i])
	}
	return p, nil
}

func (p Proxy) getTokenFromQueryString(r *http.Request) string {
	return r.URL.Query().Get(p.TokenParam)
}

func (p Proxy) getTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(p.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (p Proxy) getSite(level string) string {
	upstream, ok := p.Sites[level]
	if !ok {
		return p.DefaultSite
	}
	return upstream
}

func (p Proxy) clearQueryToken(r *http.Request) {
	u := r.URL
	q := u.Query()
	q.Del(p.TokenParam)
	u.RawQuery = q.Encode()

	p.setVar(r, CaddyVarRedirectURL, u.String())
}

func (p Proxy) setCookie(w http.ResponseWriter, token string, expiry time.Time) {
	ck := http.Cookie{
		Name:    p.CookieName,
		Value:   token,
		Expires: expiry,
		Path:    "/",
	}
	http.SetCookie(w, &ck)
}

func (p Proxy) getClaimFromToken(token string) ProxyClaim {
	if token == "" {
		return ProxyClaim{}
	}

	var claim ProxyClaim
	_, err := jwt.ParseWithClaims(token, &claim, func(token *jwt.Token) (interface{}, error) {
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
		p.log.Error("jwt token has expired: " + err.Error())
	} else if err != nil {
		p.log.Error("failed to parse token", zap.Error(err), zap.String("token", token))
	} else {
		claim.IsValid = true
	}

	return claim
}

func (p Proxy) setFlag(r *http.Request) {
	u := r.URL
	q := u.Query()
	q.Add(CookieFlag, "1")
	u.RawQuery = q.Encode()

	p.setVar(r, CaddyVarRedirectURL, u.String())
}

func (p Proxy) clearFlag(r *http.Request) {
	u := r.URL
	q := u.Query()
	q.Del(CookieFlag)
	u.RawQuery = q.Encode()

	p.setVar(r, CaddyVarRedirectURL, u.String())
}

func (p Proxy) getFlag(r *http.Request) bool {
	return r.URL.Query().Get(CookieFlag) != ""
}

// getNewToken uses a redirect to get a new token from the management API
func (p Proxy) getNewToken(_ http.ResponseWriter, r *http.Request) error {
	p.log.Info("redirecting to management API")
	p.setVar(r, CaddyVarRedirectURL, p.ManagementAPI+p.TokenPath+"?returnTo="+url.QueryEscape(p.Host+r.URL.Path))
	return nil
}

// isTrustedBot compares the user agent in the request against a list of trusted bots in the configuration and
// returns true if the user agent contains one of the configured keywords.
func (p Proxy) isTrustedBot(r *http.Request) bool {
	userAgent := strings.ToLower(r.UserAgent())
	if userAgent == "" {
		return false
	}
	for _, s := range p.TrustedBots {
		if strings.Contains(userAgent, s) {
			return true
		}
	}
	return false
}

func claimsAreValidAndDifferent(a, b ProxyClaim) bool {
	return a.IsValid && b.IsValid && !a.IssuedAt.Time.Equal(b.IssuedAt.Time)
}
