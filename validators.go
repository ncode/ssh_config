package ssh_config

import (
	"strings"
)

// Default returns the default value for a supported directive from the embedded
// OpenSSH client spec. Keyword matching is case-insensitive.
func Default(keyword string) string {
	d := supportedDirective(keyword)
	if d == nil {
		return ""
	}
	defaults := d.defaultValues()
	if len(defaults) == 0 {
		return ""
	}
	return defaults[0]
}

// SupportsMultiple reports whether a supported directive accepts multiple
// values, based on the embedded OpenSSH client spec.
func SupportsMultiple(key string) bool {
	d := supportedDirective(key)
	if d == nil {
		return false
	}
	return d.Multi
}

func supportedDirective(keyword string) *specDirective {
	if keyword == "" {
		return nil
	}
	spec, err := loadClientSpec()
	if err != nil || spec == nil {
		return nil
	}
	name := strings.ToLower(keyword)
	d := spec.byName[name]
	if d == nil || d.Status != "supported" {
		return nil
	}
	visited := map[string]bool{name: true}
	for d.AliasFor != "" {
		nextName := strings.ToLower(d.AliasFor)
		if visited[nextName] {
			return nil
		}
		visited[nextName] = true
		next := spec.byName[nextName]
		if next == nil || next.Status != "supported" {
			return nil
		}
		d = next
	}
	return d
}
