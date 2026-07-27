// Package version reports the build version.
package version

import "strings"

// value is injected for tagged builds with:
// -X github.com/bigbizze/dcg-safe/internal/version.value=<version>
var value = "dev"

// String returns a normalized version without a leading v. Untagged builds
// report dev.
func String() string {
	v := strings.TrimSpace(value)
	if v == "" || v == "(devel)" {
		return "dev"
	}
	if strings.HasPrefix(v, "v") && len(v) > 1 {
		v = v[1:]
	}
	return v
}
