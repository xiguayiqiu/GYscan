package webfp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"GYscan/internal/utils"
)

type FingerprintEngine struct {
	rules      []FingerprintRule
	categories map[string][]string
}

func NewFingerprintEngine() (*FingerprintEngine, error) {
	engine := &FingerprintEngine{
		rules:      make([]FingerprintRule, 0),
		categories: make(map[string][]string),
	}

	if err := engine.LoadDefaultRules(); err != nil {
		return nil, err
	}

	return engine, nil
}

func (e *FingerprintEngine) LoadDefaultRules() error {
	rulesPath := filepath.Join("internal", "webfp", "rules", "technologies.json")

	if _, err := os.Stat(rulesPath); err != nil {
		utils.LogWarning("指纹规则文件不存在，使用内置规则")
		e.loadBuiltInRules()
		return nil
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		utils.LogWarning("读取指纹规则文件失败: %v，使用内置规则", err)
		e.loadBuiltInRules()
		return nil
	}

	var rulesData struct {
		Technologies map[string]struct {
			Headers  map[string]string `json:"headers,omitempty"`
			HTML     map[string]string `json:"html,omitempty"`
			Scripts  []string          `json:"scripts,omitempty"`
			CSS      []string          `json:"css,omitempty"`
			Meta     map[string]string `json:"meta,omitempty"`
			Cookies  map[string]string `json:"cookies,omitempty"`
			Category string            `json:"category"`
		} `json:"technologies"`
	}

	if err := json.Unmarshal(data, &rulesData); err != nil {
		utils.LogWarning("解析指纹规则文件失败: %v，使用内置规则", err)
		e.loadBuiltInRules()
		return nil
	}

	for name, tech := range rulesData.Technologies {
		rule := FingerprintRule{
			Name:     name,
			Category: tech.Category,
		}

		for header, pattern := range tech.Headers {
			rule.Headers = append(rule.Headers, HeaderRule{
				Header:  header,
				Pattern: pattern,
			})
		}

		for selector, pattern := range tech.HTML {
			rule.HTML = append(rule.HTML, ContentRule{
				Selector: selector,
				Pattern:  pattern,
			})
		}

		for _, pattern := range tech.Scripts {
			rule.Scripts = append(rule.Scripts, URLRule{
				Pattern: pattern,
			})
		}

		for _, pattern := range tech.CSS {
			rule.CSS = append(rule.CSS, URLRule{
				Pattern: pattern,
			})
		}

		for name, pattern := range tech.Meta {
			rule.Meta = append(rule.Meta, MetaRule{
				Name:    name,
				Pattern: pattern,
			})
		}

		for name, pattern := range tech.Cookies {
			rule.Cookies = append(rule.Cookies, CookieRule{
				Name:    name,
				Pattern: pattern,
			})
		}

		e.rules = append(e.rules, rule)
		e.categories[tech.Category] = append(e.categories[tech.Category], name)
	}

	utils.LogDebug("已加载 %d 条指纹规则", len(e.rules))
	return nil
}

func (e *FingerprintEngine) loadBuiltInRules() {
	e.rules = []FingerprintRule{
		{
			Name:     "Nginx",
			Category: "Web Servers",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Nginx"},
			},
		},
		{
			Name:     "Apache",
			Category: "Web Servers",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Apache"},
			},
		},
		{
			Name:     "Microsoft IIS",
			Category: "Web Servers",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "IIS"},
				{Header: "Server", Pattern: "Microsoft-IIS"},
			},
		},
		{
			Name:     "LiteSpeed",
			Category: "Web Servers",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "LiteSpeed"},
			},
		},
		{
			Name:     "Caddy",
			Category: "Web Servers",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Caddy"},
			},
		},
		{
			Name:     "React",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "data-reactroot"},
				{Pattern: "data-react-class"},
			},
			Scripts: []URLRule{
				{Pattern: "react"},
				{Pattern: "reactjs"},
				{Pattern: "react-dom"},
			},
		},
		{
			Name:     "Vue.js",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "data-v-"},
				{Pattern: "v-if"},
				{Pattern: "v-for"},
				{Pattern: "v-on:"},
			},
			Scripts: []URLRule{
				{Pattern: "vue"},
				{Pattern: "vuejs"},
				{Pattern: "vuex"},
				{Pattern: "vue-router"},
			},
		},
		{
			Name:     "Angular",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "ng-app"},
				{Pattern: "data-ng-"},
				{Pattern: "ng-binding"},
				{Pattern: "ng-controller"},
				{Pattern: "ng-model"},
			},
			Scripts: []URLRule{
				{Pattern: "angular"},
				{Pattern: "angularjs"},
				{Pattern: "@angular"},
			},
		},
		{
			Name:     "Angular 2+",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "@angular/core"},
				{Pattern: "@angular/common"},
			},
		},
		{
			Name:     "Svelte",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "svelte"},
			},
			Scripts: []URLRule{
				{Pattern: "svelte"},
			},
		},
		{
			Name:     "SolidJS",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "solid-js"},
				{Pattern: "solid-js/"},
			},
		},
		{
			Name:     "Qwik",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "qwik"},
				{Pattern: "@builder.io/qwik"},
			},
		},
		{
			Name:     "Next.js",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "__NEXT_DATA__"},
				{Pattern: "_next/"},
				{Pattern: "data-nextjs"},
			},
			Scripts: []URLRule{
				{Pattern: "/_next/static"},
				{Pattern: "next"},
			},
		},
		{
			Name:     "Nuxt.js",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "_nuxt"},
				{Pattern: "nuxt.config"},
			},
			Scripts: []URLRule{
				{Pattern: "nuxt"},
			},
		},
		{
			Name:     "SvelteKit",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "sveltekit"},
				{Pattern: "@sveltejs/kit"},
			},
		},
		{
			Name:     "Gatsby",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "gatsby"},
				{Pattern: "__gatsby"},
			},
			Scripts: []URLRule{
				{Pattern: "gatsby"},
			},
		},
		{
			Name:     "Ember.js",
			Category: "Frontend Frameworks",
			HTML: []ContentRule{
				{Pattern: "ember-cli"},
				{Pattern: "data-ember-cli"},
			},
			Scripts: []URLRule{
				{Pattern: "ember"},
			},
		},
		{
			Name:     "Backbone.js",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "backbone"},
			},
		},
		{
			Name:     "Preact",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "preact"},
			},
		},
		{
			Name:     "Alpine.js",
			Category: "Frontend Frameworks",
			Scripts: []URLRule{
				{Pattern: "alpinejs"},
			},
		},
		{
			Name:     "Express",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Express"},
			},
		},
		{
			Name:     "NestJS",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "NestJS"},
			},
			Scripts: []URLRule{
				{Pattern: "@nestjs"},
			},
		},
		{
			Name:     "Fastify",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Fastify"},
			},
		},
		{
			Name:     "Django",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Generator", Pattern: "Django"},
			},
		},
		{
			Name:     "Flask",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Flask"},
			},
		},
		{
			Name:     "FastAPI",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "FastAPI"},
			},
		},
		{
			Name:     "Spring Boot",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Application-Context", Pattern: "Spring"},
			},
			Scripts: []URLRule{
				{Pattern: "actuator"},
			},
		},
		{
			Name:     "Quarkus",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Quarkus"},
			},
		},
		{
			Name:     "Gin",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Gin"},
			},
		},
		{
			Name:     "Echo",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Echo"},
			},
		},
		{
			Name:     "Fiber",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Fiber"},
			},
		},
		{
			Name:     "Laravel",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Laravel"},
			},
			Cookies: []CookieRule{
				{Name: "laravel_session"},
				{Name: "XSRF-TOKEN"},
			},
		},
		{
			Name:     "Symfony",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Symfony"},
			},
		},
		{
			Name:     "ASP.NET Core",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "ASP.NET"},
			},
		},
		{
			Name:     "Ruby on Rails",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Rack-Cache"},
				{Header: "X-UA-Compatible", Pattern: "Rails"},
			},
		},
		{
			Name:     "Play Framework",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Play-Framework"},
			},
		},
		{
			Name:     "Phoenix",
			Category: "Backend Frameworks",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Phoenix"},
			},
		},
		{
			Name:     "PHP",
			Category: "Programming Languages",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "PHP"},
			},
		},
		{
			Name:     "Node.js",
			Category: "Web Servers",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Express"},
			},
		},
		{
			Name:     "Python",
			Category: "Programming Languages",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Python"},
			},
		},
		{
			Name:     "Ruby",
			Category: "Programming Languages",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Ruby"},
			},
		},
		{
			Name:     "Java",
			Category: "Programming Languages",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Java"},
			},
		},
		{
			Name:     "WordPress",
			Category: "CMS",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "WordPress"},
			},
			HTML: []ContentRule{
				{Pattern: "wp-content"},
				{Pattern: "wp-includes"},
				{Pattern: "wp-admin"},
			},
			Meta: []MetaRule{
				{Name: "generator", Pattern: "WordPress"},
			},
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Drupal"},
			},
			HTML: []ContentRule{
				{Pattern: "Drupal.settings"},
				{Pattern: "drupal"},
			},
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			Headers: []HeaderRule{
				{Header: "X-Powered-By", Pattern: "Joomla"},
			},
			HTML: []ContentRule{
				{Pattern: "com_content"},
				{Pattern: "joomla"},
			},
		},
		{
			Name:     "Shopify",
			Category: "E-Commerce",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Shopify"},
			},
			HTML: []ContentRule{
				{Pattern: "cdn.shopify.com"},
				{Pattern: "/cart"},
				{Pattern: "shopify"},
			},
		},
		{
			Name:     "Wix",
			Category: "Website Builders",
			Headers: []HeaderRule{
				{Header: "X-Wix-"},
			},
			HTML: []ContentRule{
				{Pattern: "static.wixstatic.com"},
				{Pattern: "wix.com"},
			},
		},
		{
			Name:     "Squarespace",
			Category: "Website Builders",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Squarespace"},
			},
		},
		{
			Name:     "Webflow",
			Category: "Website Builders",
			HTML: []ContentRule{
				{Pattern: "webflow"},
				{Pattern: "wf-icon"},
			},
		},
		{
			Name:     "Hugo",
			Category: "Static Site Generators",
			Meta: []MetaRule{
				{Name: "generator", Pattern: "Hugo"},
			},
		},
		{
			Name:     "Jekyll",
			Category: "Static Site Generators",
			HTML: []ContentRule{
				{Pattern: "jekyll"},
			},
		},
		{
			Name:     "Docusaurus",
			Category: "Static Site Generators",
			HTML: []ContentRule{
				{Pattern: "docusaurus"},
				{Pattern: "__docusaurus"},
			},
		},
		{
			Name:     "Hexo",
			Category: "Static Site Generators",
			HTML: []ContentRule{
				{Pattern: "hexo"},
			},
		},
		{
			Name:     "Eleventy",
			Category: "Static Site Generators",
			HTML: []ContentRule{
				{Pattern: "eleventy"},
			},
		},
		{
			Name:     "Bootstrap",
			Category: "UI Frameworks",
			Scripts: []URLRule{
				{Pattern: "bootstrap"},
			},
			CSS: []URLRule{
				{Pattern: "bootstrap"},
			},
		},
		{
			Name:     "Tailwind CSS",
			Category: "UI Frameworks",
			HTML: []ContentRule{
				{Pattern: "tailwindcss"},
			},
			CSS: []URLRule{
				{Pattern: "tailwindcss"},
				{Pattern: "tailwind"},
			},
		},
		{
			Name:     "Bulma",
			Category: "UI Frameworks",
			CSS: []URLRule{
				{Pattern: "bulma"},
			},
		},
		{
			Name:     "Ant Design",
			Category: "UI Frameworks",
			Scripts: []URLRule{
				{Pattern: "antd"},
				{Pattern: "@ant-design"},
			},
		},
		{
			Name:     "Element Plus",
			Category: "UI Frameworks",
			Scripts: []URLRule{
				{Pattern: "element-plus"},
				{Pattern: "element-ui"},
			},
		},
		{
			Name:     "Material-UI",
			Category: "UI Frameworks",
			Scripts: []URLRule{
				{Pattern: "@material-ui"},
				{Pattern: "@mui"},
			},
		},
		{
			Name:     "Chakra UI",
			Category: "UI Frameworks",
			Scripts: []URLRule{
				{Pattern: "@chakra-ui"},
			},
		},
		{
			Name:     "Vuetify",
			Category: "UI Frameworks",
			Scripts: []URLRule{
				{Pattern: "vuetify"},
			},
		},
		{
			Name:     "Semantic UI",
			Category: "UI Frameworks",
			CSS: []URLRule{
				{Pattern: "semantic"},
			},
		},
		{
			Name:     "Foundation",
			Category: "UI Frameworks",
			CSS: []URLRule{
				{Pattern: "foundation"},
			},
		},
		{
			Name:     "jQuery",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "jquery"},
			},
		},
		{
			Name:     "jQuery UI",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "jquery-ui"},
			},
		},
		{
			Name:     "Lodash",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "lodash"},
			},
		},
		{
			Name:     "Underscore",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "underscore"},
			},
		},
		{
			Name:     "Axios",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "axios"},
			},
		},
		{
			Name:     "Moment.js",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "moment"},
			},
		},
		{
			Name:     "Day.js",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "dayjs"},
			},
		},
		{
			Name:     "Chart.js",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "chart.js"},
				{Pattern: "chartjs"},
			},
		},
		{
			Name:     "D3.js",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "d3"},
			},
		},
		{
			Name:     "Three.js",
			Category: "JavaScript Libraries",
			Scripts: []URLRule{
				{Pattern: "three"},
			},
		},
		{
			Name:     "Redux",
			Category: "State Management",
			Scripts: []URLRule{
				{Pattern: "redux"},
			},
		},
		{
			Name:     "Redux Toolkit",
			Category: "State Management",
			Scripts: []URLRule{
				{Pattern: "@reduxjs/toolkit"},
			},
		},
		{
			Name:     "Pinia",
			Category: "State Management",
			Scripts: []URLRule{
				{Pattern: "pinia"},
			},
		},
		{
			Name:     "Zustand",
			Category: "State Management",
			Scripts: []URLRule{
				{Pattern: "zustand"},
			},
		},
		{
			Name:     "MobX",
			Category: "State Management",
			Scripts: []URLRule{
				{Pattern: "mobx"},
			},
		},
		{
			Name:     "Recoil",
			Category: "State Management",
			Scripts: []URLRule{
				{Pattern: "recoil"},
			},
		},
		{
			Name:     "Webpack",
			Category: "Build Tools",
			Scripts: []URLRule{
				{Pattern: "webpack"},
				{Pattern: "webpackJsonp"},
			},
		},
		{
			Name:     "Vite",
			Category: "Build Tools",
			Scripts: []URLRule{
				{Pattern: "vite"},
				{Pattern: "/@vite/client"},
			},
		},
		{
			Name:     "esbuild",
			Category: "Build Tools",
			Scripts: []URLRule{
				{Pattern: "esbuild"},
			},
		},
		{
			Name:     "Babel",
			Category: "Build Tools",
			Scripts: []URLRule{
				{Pattern: "babel"},
				{Pattern: "__extends"},
			},
		},
		{
			Name:     "TypeScript",
			Category: "Programming Languages",
			Scripts: []URLRule{
				{Pattern: "typescript"},
				{Pattern: "tslib"},
			},
		},
		{
			Name:     "Cloudflare",
			Category: "CDN",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "cloudflare"},
				{Header: "CF-RAY"},
				{Header: "CF-Cache-Status"},
			},
		},
		{
			Name:     "Akamai",
			Category: "CDN",
			Headers: []HeaderRule{
				{Header: "X-Cache"},
				{Header: "X-Akamai-"},
			},
		},
		{
			Name:     "Fastly",
			Category: "CDN",
			Headers: []HeaderRule{
				{Header: "X-Cache", Pattern: "FASTLY"},
				{Header: "Fastly-"},
			},
		},
		{
			Name:     "Vercel",
			Category: "Hosting",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Vercel"},
				{Header: "x-vercel-id"},
			},
		},
		{
			Name:     "Netlify",
			Category: "Hosting",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Netlify"},
			},
		},
		{
			Name:     "AWS Amplify",
			Category: "Hosting",
			Headers: []HeaderRule{
				{Header: "Server", Pattern: "Amplify"},
			},
		},
		{
			Name:     "AWS Lambda",
			Category: "Serverless",
			Headers: []HeaderRule{
				{Header: "x-amz-invocation-id"},
			},
		},
		{
			Name:     "Google Analytics",
			Category: "Analytics",
			Scripts: []URLRule{
				{Pattern: "google-analytics.com"},
				{Pattern: "googletagmanager"},
				{Pattern: "gtag"},
			},
		},
		{
			Name:     "Hotjar",
			Category: "Analytics",
			Scripts: []URLRule{
				{Pattern: "hotjar"},
				{Pattern: "hj"},
			},
		},
		{
			Name:     "Meta Pixel",
			Category: "Analytics",
			Scripts: []URLRule{
				{Pattern: "connect.facebook.net"},
				{Pattern: "fbevents"},
			},
		},
		{
			Name:     "Matomo",
			Category: "Analytics",
			Scripts: []URLRule{
				{Pattern: "matomo"},
				{Pattern: "piwik"},
			},
		},
		{
			Name:     "Plausible",
			Category: "Analytics",
			Scripts: []URLRule{
				{Pattern: "plausible"},
			},
		},
		{
			Name:     "Fathom",
			Category: "Analytics",
			Scripts: []URLRule{
				{Pattern: "fathom"},
			},
		},
		{
			Name:     "Auth0",
			Category: "Authentication",
			HTML: []ContentRule{
				{Pattern: "auth0"},
				{Pattern: "auth0.com"},
			},
		},
		{
			Name:     "Firebase",
			Category: "Authentication",
			Scripts: []URLRule{
				{Pattern: "firebase"},
				{Pattern: "firebasejs"},
			},
		},
		{
			Name:     "Okta",
			Category: "Authentication",
			HTML: []ContentRule{
				{Pattern: "okta"},
				{Pattern: "oktacdn"},
			},
		},
		{
			Name:     "NextAuth",
			Category: "Authentication",
			Scripts: []URLRule{
				{Pattern: "next-auth"},
			},
		},
		{
			Name:     "Supabase",
			Category: "Authentication",
			Scripts: []URLRule{
				{Pattern: "supabase"},
			},
		},
		{
			Name:     "Stripe",
			Category: "Payment",
			Scripts: []URLRule{
				{Pattern: "js.stripe.com"},
				{Pattern: "@stripe/stripe-js"},
			},
		},
		{
			Name:     "PayPal",
			Category: "Payment",
			Scripts: []URLRule{
				{Pattern: "paypal"},
				{Pattern: "js.paypal.com"},
			},
		},
	}
}

func (e *FingerprintEngine) Detect(ctx *DetectionContext) []Technology {
	detected := make(map[string]Technology)

	for _, rule := range e.rules {
		confidence := 0.0
		detectedBy := []string{}

		for _, hRule := range rule.Headers {
			if ctx.Headers != nil {
				if value, ok := ctx.Headers[hRule.Header]; ok {
					if strings.Contains(strings.ToLower(value), strings.ToLower(hRule.Pattern)) {
						confidence += 30.0
						detectedBy = append(detectedBy, fmt.Sprintf("header:%s", hRule.Header))
						if hRule.Version != "" {
							if v := extractVersionFromString(value); v != "" {
								if tech, exists := detected[rule.Name]; exists {
									tech.Version = v
									detected[rule.Name] = tech
								}
							}
						}
					}
				}
			}
		}

		for _, cRule := range rule.Cookies {
			if ctx.Cookies != nil {
				if value, ok := ctx.Cookies[cRule.Name]; ok {
					if cRule.Pattern == "" || strings.Contains(strings.ToLower(value), strings.ToLower(cRule.Pattern)) {
						confidence += 25.0
						detectedBy = append(detectedBy, fmt.Sprintf("cookie:%s", cRule.Name))
					}
				}
			}
		}

		for _, sRule := range rule.Scripts {
			for _, script := range ctx.Scripts {
				if strings.Contains(strings.ToLower(script), strings.ToLower(sRule.Pattern)) {
					confidence += 20.0
					detectedBy = append(detectedBy, "script")
					break
				}
			}
		}

		for _, cssRule := range rule.CSS {
			for _, css := range ctx.CSS {
				if strings.Contains(strings.ToLower(css), strings.ToLower(cssRule.Pattern)) {
					confidence += 15.0
					detectedBy = append(detectedBy, "css")
					break
				}
			}
		}

		for _, mRule := range rule.Meta {
			if value, ok := ctx.Meta[mRule.Name]; ok {
				if strings.Contains(strings.ToLower(value), strings.ToLower(mRule.Pattern)) {
					confidence += 35.0
					detectedBy = append(detectedBy, fmt.Sprintf("meta:%s", mRule.Name))
					if mRule.Version != "" {
						if v := extractVersionFromString(value); v != "" {
							if tech, exists := detected[rule.Name]; exists {
								tech.Version = v
								detected[rule.Name] = tech
							}
						}
					}
				}
			}
		}

		for _, hRule := range rule.HTML {
			if strings.Contains(strings.ToLower(ctx.Body), strings.ToLower(hRule.Pattern)) {
				confidence += 10.0
				detectedBy = append(detectedBy, "html")
			}
		}

		if confidence >= 10.0 {
			tech := Technology{
				Name:       rule.Name,
				Category:   rule.Category,
				Confidence: confidence,
				DetectedBy: detectedBy,
			}
			detected[rule.Name] = tech
		}
	}

	results := make([]Technology, 0, len(detected))
	for _, tech := range detected {
		if tech.Confidence >= 20.0 {
			results = append(results, tech)
		}
	}

	return results
}

func extractVersionFromString(s string) string {
	versionPattern := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)`)
	matches := versionPattern.FindStringSubmatch(s)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (e *FingerprintEngine) GetCategories() []string {
	categories := make([]string, 0, len(e.categories))
	for cat := range e.categories {
		categories = append(categories, cat)
	}
	return categories
}

func (e *FingerprintEngine) GetRulesByCategory(category string) []FingerprintRule {
	var rules []FingerprintRule
	for _, rule := range e.rules {
		if rule.Category == category {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (e *FingerprintEngine) AddCustomRule(rule FingerprintRule) {
	e.rules = append(e.rules, rule)
	e.categories[rule.Category] = append(e.categories[rule.Category], rule.Name)
}

func (e *FingerprintEngine) GetTotalRules() int {
	return len(e.rules)
}
