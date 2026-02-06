package webfp

import (
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type HTMLParser struct {
	doc *goquery.Document
}

func NewHTMLParser(html string) (*HTMLParser, error) {
	reader := strings.NewReader(html)
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return nil, err
	}
	return &HTMLParser{doc: doc}, nil
}

func (p *HTMLParser) ExtractScripts() []string {
	var scripts []string
	p.doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			scripts = append(scripts, src)
		}
	})
	return scripts
}

func (p *HTMLParser) ExtractInlineScripts() []string {
	var scripts []string
	p.doc.Find("script:not([src])").Each(func(i int, s *goquery.Selection) {
		scripts = append(scripts, s.Text())
	})
	return scripts
}

func (p *HTMLParser) ExtractCSS() []string {
	var cssFiles []string
	p.doc.Find("link[rel='stylesheet']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			cssFiles = append(cssFiles, href)
		}
	})
	return cssFiles
}

func (p *HTMLParser) ExtractMetaTags() map[string]string {
	meta := make(map[string]string)
	p.doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		if name, exists := s.Attr("name"); exists {
			if content, exists := s.Attr("content"); exists {
				meta[name] = content
			}
		}
		if property, exists := s.Attr("property"); exists {
			if content, exists := s.Attr("content"); exists {
				meta[property] = content
			}
		}
	})
	return meta
}

func (p *HTMLParser) ExtractGenerator() string {
	meta := p.doc.Find("meta[name='generator']")
	if gen, exists := meta.Attr("content"); exists {
		return gen
	}
	return ""
}

func (p *HTMLParser) ExtractComments() []string {
	var comments []string
	html, _ := p.doc.Html()
	commentPattern := regexp.MustCompile(`<!--(.*?)-->`)
	matches := commentPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			comments = append(comments, match[1])
		}
	}
	return comments
}

func (p *HTMLParser) ExtractTitle() string {
	title := p.doc.Find("title").First()
	return title.Text()
}

func (p *HTMLParser) ExtractFavicons() []string {
	var favicons []string
	p.doc.Find("link[rel*='icon']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			favicons = append(favicons, href)
		}
	})
	return favicons
}

func (p *HTMLParser) ExtractDoctype() string {
	doc := p.doc.Find("*").First()
	if doc.Length() > 0 {
		prev := doc.Prev()
		if prev.Length() > 0 {
			if prev.Length() > 0 && prev.Get(0).Type == 7 {
				return prev.Text()
			}
		}
	}
	return ""
}

func (p *HTMLParser) ExtractBodyText() string {
	return p.doc.Find("body").Text()
}

func (p *HTMLParser) HasAttribute(selector, attr string) bool {
	selection := p.doc.Find(selector).First()
	_, exists := selection.Attr(attr)
	return exists
}

func (p *HTMLParser) GetAttributeValue(selector, attr string) string {
	selection := p.doc.Find(selector).First()
	val, _ := selection.Attr(attr)
	return val
}

func (p *HTMLParser) FindPatterns(patterns []string) map[string][]string {
	results := make(map[string][]string)
	bodyText := p.doc.Text()
	for _, pattern := range patterns {
		if strings.Contains(bodyText, pattern) {
			results[pattern] = append(results[pattern], "body")
		}
	}
	return results
}

func (p *HTMLParser) SearchInSource(searchText string) bool {
	html, _ := p.doc.Html()
	return strings.Contains(html, searchText)
}

func ExtractVersion(text string) string {
	versionPattern := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)`)
	matches := versionPattern.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func ExtractFrameworkIndicators(html string) map[string]string {
	indicators := make(map[string]string)

	if strings.Contains(html, "data-reactroot") {
		indicators["React"] = "data-reactroot"
	}
	if strings.Contains(html, "data-nextjs") {
		indicators["Next.js"] = "data-nextjs"
	}
	if strings.Contains(html, "data-v-") {
		indicators["Vue.js"] = "data-v-"
	}
	if strings.Contains(html, "ng-app") {
		indicators["AngularJS"] = "ng-app"
	}
	if strings.Contains(html, "_nuxt") {
		indicators["Nuxt.js"] = "_nuxt"
	}
	if strings.Contains(html, "__NEXT_DATA__") {
		indicators["Next.js"] = "__NEXT_DATA__"
	}
	if strings.Contains(html, "gatsby") {
		indicators["Gatsby"] = "gatsby"
	}
	if strings.Contains(html, "svelte") {
		indicators["Svelte"] = "svelte"
	}
	if strings.Contains(html, "ember-cli") {
		indicators["Ember.js"] = "ember-cli"
	}
	if strings.Contains(html, "backbone") {
		indicators["Backbone.js"] = "backbone"
	}

	return indicators
}

func DetectCSP(html string) string {
	cspPattern := regexp.MustCompile(`<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*content=["']([^"']+)["']`)
	matches := cspPattern.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func DetectPrerender(html string) bool {
	prerenderPatterns := []string{
		"<prerender",
		"prerender.io",
		"prerender.cloud",
	}
	for _, pattern := range prerenderPatterns {
		if strings.Contains(html, pattern) {
			return true
		}
	}
	return false
}
