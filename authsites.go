package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type AuthSites map[string]string

func (a *AuthSites) Decode(input string) error {
	*a = make(AuthSites)
	re, err := regexp.Compile(`^\w+://`)
	if err != nil {
		return err
	}

	sites := strings.Split(input, ",")
	for _, s := range sites {
		if s == "" {
			continue
		}

		level, site, found := strings.Cut(s, ":")
		if !found {
			return fmt.Errorf("invalid input format: %v", s)
		}

		// ensure url can parse it
		if !re.MatchString(site) {
			site = "http://" + site
		}

		u, err := url.Parse(site)
		if err != nil {
			return err
		}

		site = u.Host
		if u.Port() == "" {
			site += ":80"
		}

		(*a)[level] = site
	}

	return nil
}
