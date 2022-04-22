package lib

import (
	"regexp"
	"strings"

	"golang.org/x/net/webdav"
)

// Rule is a dissalow/allow rule.
type Rule struct {
	Regex  bool
	Allow  bool
	Modify bool
	Path   string
	Regexp *regexp.Regexp
}

// User contains the settings of each user.
type User struct {
	Username string
	Password string
	Scope    string
	Modify   bool
	Rules    []*Rule
	Handler  *webdav.Handler
}

// Allowed checks if the user has permission to access a directory/file
func (u User) Allowed(url string, noModification bool) bool {
	isAllowed := false
	for _, rule := range u.Rules[1:len(u.Rules)] {
		if rule.Regex {
			if rule.Regexp.MatchString(url) {
				isAllowed = rule.Allow && (noModification || rule.Modify)
			}
		} else if rule.Path == url {
			return rule.Allow && (noModification || rule.Modify)
		} else if strings.HasPrefix(rule.Path, url) {
			return true
		} else if strings.HasPrefix(url, rule.Path) {
			isAllowed = rule.Allow && (noModification || rule.Modify)
		}
	}

	return isAllowed

}
