package trapdoor

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("trapdoor", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("trapdoor", "before", "basic_auth")
}

var bannedIPs = map[string]time.Time{}

type Middleware struct {
	BanAction   int            `json:"action,omitempty"`
	BanDuration caddy.Duration `json:"duration,omitempty"`

	MatcherSetsRaw []caddy.ModuleMap      `json:"matchers" caddy:"namespace=http.matchers"`
	MatcherSets    []caddyhttp.MatcherSet `json:"-"`

	logger *zap.Logger
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.trapdoor",
		New: func() caddy.Module {
			return new(Middleware)
		},
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	matcherSets, _ := ctx.LoadModule(m, "MatcherSetsRaw")
	for _, modMap := range matcherSets.([]map[string]any) {
		var ms caddyhttp.MatcherSet
		for _, modIface := range modMap {
			if mod, ok := modIface.(caddyhttp.RequestMatcherWithError); ok {
				ms = append(ms, mod)
				continue
			}

			if mod, ok := modIface.(caddyhttp.RequestMatcher); ok {
				ms = append(ms, mod)
				continue
			}

			return fmt.Errorf("module is not a request matcher: %T", modIface)
		}

		m.MatcherSets = append(m.MatcherSets, ms)
	}

	return nil
}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Sugar().Errorf("net.SplitHostPort(%s) failed: %s", r.RemoteAddr, err.Error())
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	if v, ok := bannedIPs[ipStr]; ok {
		if v.Compare(time.Now()) != -1 {
			return caddyhttp.Error(m.BanAction, nil)
		}

		delete(bannedIPs, ipStr)
	}

	if requestMatches(m, r) {
		bannedIPs[ipStr] = time.Now().Add(time.Duration(m.BanDuration))
		return caddyhttp.Error(m.BanAction, nil)
	}

	return next.ServeHTTP(w, r)
}

func requestMatches(m Middleware, r *http.Request) bool {
	for _, ms := range m.MatcherSets {
		if ms.Match(r) {
			return true
		}
	}

	return false
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "match":
				matcherSet, err := caddyhttp.ParseCaddyfileNestedMatcherSet(d)
				if err != nil {
					return d.Errf("failed to parse match: %w", err)
				}

				m.MatcherSetsRaw = append(m.MatcherSetsRaw, matcherSet)

			case "action":
				if !d.NextArg() {
					return d.ArgErr()
				}

				action := d.Val()
				if action == "" {
					return d.Errf("invalid trapdoor.action: %s", action)
				}

				actionInt, err := strconv.ParseInt(action, 10, 64)
				if err != nil {
					return d.Errf("invalid trapdoor.action: %s", action)
				}

				m.BanAction = int(actionInt)

			case "duration":
				if !d.NextArg() {
					return d.ArgErr()
				}

				val := d.Val()
				if val == "" {
					return d.Errf("invalid trapdoor.duration: %s", val)
				}

				duration, err := caddy.ParseDuration(val)
				if err != nil {
					return d.Errf("invalid trapdoor.duration: %s => %s", val, err)
				}

				m.BanDuration = caddy.Duration(duration)

			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	return nil
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(helper.Dispenser)
	return m, err
}

var (
	_ caddy.Provisioner = (*Middleware)(nil)
	// _ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
