package input

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// ExtractScriptSrcs parses an HTML document and returns all <script src="...">
// URLs found within it, resolved as absolute URLs against baseURL.
// Results are deduplicated before returning.
func ExtractScriptSrcs(htmlContent []byte, baseURL string) ([]string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	doc, err := html.Parse(strings.NewReader(string(htmlContent)))
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var srcs []string

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					val := strings.TrimSpace(attr.Val)
					// Skip empty, data-URI, and blob-URI values — they are not fetchable URLs.
					if val == "" || strings.HasPrefix(val, "data:") || strings.HasPrefix(val, "blob:") {
						continue
					}
					ref, parseErr := url.Parse(val)
					if parseErr != nil {
						continue
					}
					resolved := base.ResolveReference(ref).String()
					if _, exists := seen[resolved]; !exists {
						seen[resolved] = struct{}{}
						srcs = append(srcs, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)

	return srcs, nil
}
