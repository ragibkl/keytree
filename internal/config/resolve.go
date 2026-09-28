package config

import (
	"maps"
	"path"
	"slices"
	"sort"
)

// Access is what one server should allow: local account -> user names.
type Access struct {
	// Matched lists the server patterns that matched, in sorted order.
	Matched []string
	// Accounts maps each local account to the sorted, de-duplicated users
	// allowed to log in to it. An account with no users is kept: it means
	// access was removed on purpose.
	Accounts map[string][]string
}

// Resolve returns the access for the server called name. Every matching
// entry applies; each account gets the union of its lists.
func (f *File) Resolve(name string) Access {
	a := Access{Accounts: map[string][]string{}}
	sets := map[string]map[string]bool{}
	for _, pattern := range slices.Sorted(maps.Keys(f.Servers)) {
		if ok, _ := path.Match(pattern, name); !ok {
			continue
		}
		a.Matched = append(a.Matched, pattern)
		for account, g := range f.Servers[pattern] {
			set := sets[account]
			if set == nil {
				set = map[string]bool{}
				sets[account] = set
			}
			for _, u := range g.Users {
				set[u] = true
			}
			for _, gr := range g.Groups {
				for _, u := range f.Groups[gr] {
					set[u] = true
				}
			}
		}
	}
	for account, set := range sets {
		users := make([]string, 0, len(set))
		for u := range set {
			users = append(users, u)
		}
		sort.Strings(users)
		a.Accounts[account] = users
	}
	return a
}
