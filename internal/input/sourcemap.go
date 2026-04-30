package input

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// SourceMap holds the fields from a JavaScript Source Map (Spec v3) that are
// relevant for dependency-confusion analysis.  The full spec contains additional
// fields (mappings, names, …) that are intentionally ignored here.
type SourceMap struct {
	Version int    `json:"version"`
	File    string `json:"file"`

	// Sources is the list of original source file paths/URLs that were combined
	// to produce the generated bundle.  These paths often contain "node_modules/"
	// segments that reveal the npm packages the application depends on.
	Sources []string `json:"sources"`

	// SourcesContent mirrors Sources 1-to-1.  Each entry is either the full
	// text of the original source file (a JSON string) or null.  We decode into
	// []interface{} so we can safely distinguish strings from JSON null values.
	SourcesContent []interface{} `json:"sourcesContent"`
}

// sourceMappingURLRe matches the sourceMappingURL annotation that bundlers
// (webpack, Rollup, esbuild, Parcel, …) append to the end of generated JS files.
//
// It handles:
//   - Modern  //# sourceMappingURL=…   (Chrome convention, current standard)
//   - Legacy  //@ sourceMappingURL=…   (old Firefox / IE convention)
//   - Block   /*# sourceMappingURL=… */ (used by CSS and some JS tools)
//
// Inline data: URIs (base64-embedded maps) are returned as-is; the caller is
// responsible for filtering them out when a real URL is required.
var sourceMappingURLRe = regexp.MustCompile(
	`(?m)(?://|/\*)[#@]\s+sourceMappingURL=([^\s*]+)`,
)

// nodeModulesRe extracts the npm package name from any path segment that
// contains "node_modules/".  It recognises both scoped packages
// (@scope/package) and plain unscoped packages.
//
// Examples of matched strings:
//
//	"webpack:///./node_modules/react/index.js"          → "react"
//	"webpack:///./node_modules/@redux/core/dist/core.js" → "@redux/core"
//	"/home/user/project/node_modules/lodash/lodash.js"  → "lodash"
var nodeModulesRe = regexp.MustCompile(
	`node_modules/((?:@[a-z0-9_.\-]+/[a-z0-9_.\-]+)|(?:[a-z0-9_.\-]+))`,
)

// ParseSourceMap decodes raw source-map JSON bytes into a SourceMap struct.
// It returns an error if the payload is not valid JSON or cannot be unmarshalled
// into the expected shape.
func ParseSourceMap(data []byte) (*SourceMap, error) {
	var sm SourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, err
	}
	return &sm, nil
}

// ExtractSourceMapURL scans the content of a JavaScript file for a
// sourceMappingURL annotation and returns the resolved absolute URL of the
// referenced map file.
//
// The baseURL argument is used to resolve relative map paths against the URL
// of the JS file that was fetched.  If baseURL is empty the raw annotation
// value is returned without resolution.
//
// An empty string is returned when:
//   - no annotation is present in the content
//   - the annotation value is empty
//   - the annotation is an inline data: URI (already embedded — nothing to fetch)
//   - URL parsing or resolution fails
func ExtractSourceMapURL(jsContent []byte, baseURL string) string {
	matches := sourceMappingURLRe.FindSubmatch(jsContent)
	if len(matches) < 2 {
		return ""
	}

	mapRef := strings.TrimSpace(string(matches[1]))
	if mapRef == "" || strings.HasPrefix(mapRef, "data:") {
		return ""
	}

	// No base — return the raw value and let the caller decide.
	if baseURL == "" {
		return mapRef
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return mapRef
	}
	ref, err := url.Parse(mapRef)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// PackagesFromSources inspects each entry in the sources array of a source map
// and extracts npm package names by looking for "node_modules/<pkg>" path
// segments.
//
// Both scoped (@scope/pkg) and unscoped (pkg) packages are recognised.
// The returned slice is deduplicated; order is determined by first appearance.
func PackagesFromSources(sources []string) []string {
	seen := make(map[string]struct{})
	var pkgs []string

	for _, src := range sources {
		for _, match := range nodeModulesRe.FindAllStringSubmatch(src, -1) {
			if len(match) > 1 && match[1] != "" {
				pkg := match[1]
				if _, exists := seen[pkg]; !exists {
					seen[pkg] = struct{}{}
					pkgs = append(pkgs, pkg)
				}
			}
		}
	}
	return pkgs
}

// SourceContents returns the non-null string entries from the sourcesContent
// array of a parsed source map.
//
// Each returned string is the complete text of one original source file before
// it was minified / bundled.  These strings are ideal for feeding into the
// JS package extractor because they retain the original require() / import
// statements and are not obfuscated by minification.
//
// Null entries (encoded as JSON null, decoded as nil interface{}) and empty
// strings are silently skipped.
func SourceContents(sm *SourceMap) []string {
	var contents []string
	for _, entry := range sm.SourcesContent {
		if s, ok := entry.(string); ok && s != "" {
			contents = append(contents, s)
		}
	}
	return contents
}
