package cache

import (
	"fmt"
	"regexp"
	"strings"
)

type Matcher struct {
	raw string
	re  *regexp.Regexp
}

func CompileMatchers(patterns []string) ([]Matcher, error) {
	out := make([]Matcher, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := compilePattern(p)
		if err != nil {
			return nil, err
		}
		out = append(out, Matcher{raw: p, re: re})
	}
	return out, nil
}

func (m Matcher) Match(path string) bool {
	return m.re.MatchString(path)
}

func compilePattern(p string) (*regexp.Regexp, error) {
	if p == "/" {
		return regexp.Compile("^/$")
	}
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	// '*' matches any characters including '/'
	expr := "^" + strings.Join(parts, ".*") + "$"
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid cache pattern %q: %w", p, err)
	}
	return re, nil
}
