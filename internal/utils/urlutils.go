package utils

import (
	"net"
	"net/url"
	"strings"
)

// GetBaseURL returns the scheme and host part of a URL.
func GetBaseURL(rawURL string) (string, error) {
		u, err := url.Parse(rawURL)
		if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// IsSameDomain checks if two URLs belong to the same domain.
func IsSameDomain(url1, url2 string) bool {
	host1, err := GetHost(url1)
	if err != nil {
		return false
	}
	host2, err := GetHost(url2)
		if err != nil {
	return false
}
	return host1 == host2
}

// GetHost extracts the host from a URL.
func GetHost(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// IsLocalFilePath returns true when the target string looks like a local
// filesystem path rather than a URL (Unix absolute/relative, Windows absolute).
func IsLocalFilePath(target string) bool {
	return strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "../") ||
		strings.HasPrefix(target, ".\\") ||
		strings.HasPrefix(target, "..\\") ||
		// Windows absolute path: C:\ or D:/
		(len(target) > 2 && target[1] == ':' && (target[2] == '\\' || target[2] == '/'))
}

// NormalizeTarget ensures a scan target has a proper URL scheme.
//
// Rules:
//   - Already has http:// or https://  →  returned unchanged, autoScheme=false
//   - Looks like a local file path      →  returned unchanged, autoScheme=false
//   - Anything else (bare hostname /
//     subdomain, e.g. "sub.example.com") →  "https://" is prepended,
//     autoScheme=true (signals the fetch layer to retry with http:// on failure)
func NormalizeTarget(target string) (normalizedURL string, autoScheme bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return target, false
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target, false
	}
	if IsLocalFilePath(target) {
		return target, false
	}
	// Bare hostname or subdomain — auto-promote to HTTPS.
	return "https://" + target, true
}

// IsLikelyJSFile returns true when the URL path ends with a recognised
// JavaScript or TypeScript file extension. Used to decide whether a target
// should be fetched directly as a script or navigated to with a headless
// browser in search of dynamically loaded scripts.
func IsLikelyJSFile(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, ext := range []string{".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".map"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// IsInternalDomain returns true when the URL's hostname matches patterns that
// are commonly used for internal / private infrastructure — corporate intranets,
// dev environments, staging systems, and RFC-1918 address space — where headless
// browser crawling is neither useful nor safe (the host is likely unreachable
// from the public internet, or it may belong to a private network that should
// not be probed with a full browser session).
//
// Filtered categories:
//
//   - Loopback / link-local addresses (127.0.0.1, ::1, 169.254.x.x)
//   - RFC-1918 private IPv4 ranges (10/8, 172.16/12, 192.168/16)
//   - IPv6 Unique Local Addresses (fc00::/7)
//   - TLDs reserved for internal use: .local, .internal, .corp, .lan,
//     .intranet, .test, .localhost
//   - Hostname segments that are unambiguous internal environment markers:
//     "int", "internal", "intranet", "corp", "dev", "stage", "staging",
//     "local", "test", "uat", "qa", "localhost"
//     (e.g.  fbproxy.int.fgs.example.com  or  app.dev.example.com)
func IsInternalDomain(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return false
	}

	// ── Loopback shorthand ───────────────────────────────────────────────────
	if host == "localhost" {
		return true
	}

	// ── IP address checks ────────────────────────────────────────────────────
	if ip := net.ParseIP(host); ip != nil {
		// Loopback (127.0.0.0/8, ::1)
		if ip.IsLoopback() {
			return true
		}
		// Link-local (169.254.0.0/16, fe80::/10)
		if ip.IsLinkLocalUnicast() {
			return true
		}
		// Private ranges
		privateRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7", // IPv6 ULA
		}
		for _, cidr := range privateRanges {
			_, network, parseErr := net.ParseCIDR(cidr)
			if parseErr == nil && network.Contains(ip) {
				return true
			}
		}
		return false
	}

	// ── Internal TLD suffixes ────────────────────────────────────────────────
	internalTLDs := []string{
		".local", ".internal", ".corp", ".lan",
		".intranet", ".test", ".localhost",
	}
	for _, tld := range internalTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}

	// ── Internal subdomain segment markers ───────────────────────────────────
	// Checked against every dot-separated label so that patterns like
	// "fbproxy.int.fgs.example.com" or "app.dev.example.com" are caught
	// regardless of their position in the hostname.
	internalSegments := map[string]bool{
		"int":      true,
		"internal": true,
		"intranet": true,
		"corp":     true,
		"dev":      true,
		"stage":    true,
		"staging":  true,
		"local":    true,
		"test":     true,
		"uat":      true,
		"qa":       true,
		"localhost": true,
	}
	parts := strings.Split(host, ".")
	// Skip the last label (TLD) to avoid false-positives on real TLDs like .dev
	checkParts := parts
	if len(parts) > 1 {
		checkParts = parts[:len(parts)-1]
	}
	for _, p := range checkParts {
		if internalSegments[p] {
			return true
		}
	}

	return false
}
