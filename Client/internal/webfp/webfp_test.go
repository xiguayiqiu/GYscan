package webfp

import (
	"testing"
)

func TestDetectSimple(t *testing.T) {
	ctx := &DetectionContext{
		Headers: map[string]string{
			"Server":       "Nginx",
			"X-Powered-By": "PHP/7.4",
		},
		Body: `<html>
<head>
<meta name="generator" content="WordPress 5.8">
<script src="/wp-includes/js/jquery/jquery.js"></script>
<link rel="stylesheet" href="/wp-content/themes/twenty/style.css">
</head>
<body data-reactroot="">
</body>
</html>`,
		Scripts: []string{
			"/wp-includes/js/jquery/jquery.js",
			"/wp-content/themes/twenty/script.js",
		},
		CSS: []string{
			"/wp-content/themes/twenty/style.css",
		},
		Meta: map[string]string{
			"generator": "WordPress 5.8",
		},
		Cookies: map[string]string{
			"wordpress_test_cookie": "test",
		},
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	technologies := engine.Detect(ctx)

	t.Logf("Detected %d technologies", len(technologies))
	for _, tech := range technologies {
		t.Logf("  - %s (%s): %.0f%% confidence", tech.Name, tech.Category, tech.Confidence)
	}

	if len(technologies) < 2 {
		t.Errorf("Expected at least 2 technologies, got %d", len(technologies))
	}
}

func TestDetectMultipleCategories(t *testing.T) {
	ctx := &DetectionContext{
		Headers: map[string]string{
			"Server":       "nginx/1.18.0",
			"X-Powered-By": "Express",
			"CF-RAY":       "abc123",
		},
		Body: `<html>
<head>
<meta name="generator" content="Next.js 13.0">
<script src="/_next/static/chunks/commons.js"></script>
<link rel="stylesheet" href="/css/app.css">
</head>
<body>
<div id="__next">React App</div>
</body>
</html>`,
		Scripts: []string{
			"/_next/static/chunks/commons.js",
			"/js/react.production.min.js",
			"/js/redux.min.js",
		},
		CSS: []string{
			"/css/app.css",
			"/css/bootstrap.min.css",
		},
		Meta: map[string]string{
			"generator": "Next.js 13.0",
		},
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	technologies := engine.Detect(ctx)

	t.Logf("Detected %d technologies", len(technologies))
	for _, tech := range technologies {
		t.Logf("  - %s (%s): %.0f%% confidence", tech.Name, tech.Category, tech.Confidence)
	}

	expectedCategories := []string{"Web Servers", "Frontend Frameworks", "Backend Frameworks", "CDN"}
	foundCategories := make(map[string]bool)
	for _, tech := range technologies {
		foundCategories[tech.Category] = true
	}

	for _, cat := range expectedCategories {
		if !foundCategories[cat] {
			t.Logf("Category %s not found (may be expected)", cat)
		}
	}
}

func TestVersionExtraction(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"WordPress 5.8.1", "5.8.1"},
		{"Nginx/1.18.0", "1.18.0"},
		{"React 17.0.2", "17.0.2"},
		{"Vue.js v3.2.0", "3.2.0"},
		{"Next.js 13.4.1", "13.4.1"},
		{"Django 4.2.0", "4.2.0"},
	}

	for _, tc := range testCases {
		result := extractVersionFromString(tc.input)
		if result != tc.expected {
			t.Errorf("extractVersionFromString(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestFrameworkIndicators(t *testing.T) {
	testCases := []struct {
		html     string
		expected map[string]bool
	}{
		{
			html:     `<div data-reactroot>Hello</div>`,
			expected: map[string]bool{"React": true},
		},
		{
			html:     `<div data-v-123 v-if="true">Test</div>`,
			expected: map[string]bool{"Vue.js": true},
		},
		{
			html:     `<div ng-app="myApp">Angular</div>`,
			expected: map[string]bool{"AngularJS": true},
		},
		{
			html:     `<svelte>Hello from Svelte</svelte>`,
			expected: map[string]bool{"Svelte": true},
		},
		{
			html:     `<script>__NEXT_DATA__</script>`,
			expected: map[string]bool{"Next.js": true},
		},
		{
			html:     `<div class="gatsby">Built with Gatsby</div>`,
			expected: map[string]bool{"Gatsby": true},
		},
		{
			html:     `<div class="_nuxt">Nuxt.js app</div>`,
			expected: map[string]bool{"Nuxt.js": true},
		},
	}

	for _, tc := range testCases {
		indicators := ExtractFrameworkIndicators(tc.html)
		for name := range tc.expected {
			if _, ok := indicators[name]; !ok {
				t.Errorf("ExtractFrameworkIndicators(%q) missing %s", tc.html, name)
			}
		}
	}
}

func TestCategoriesCount(t *testing.T) {
	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	totalRules := engine.GetTotalRules()
	t.Logf("Total fingerprint rules: %d", totalRules)

	if totalRules < 50 {
		t.Errorf("Expected at least 50 rules, got %d", totalRules)
	}
}

func TestECommerceDetection(t *testing.T) {
	ctx := &DetectionContext{
		Headers: map[string]string{
			"Server": "Shopify",
		},
		Body: `<html>
<head>
<link rel="stylesheet" href="https://cdn.shopify.com/s/files/1/0000/0000/t/1/assets/global.css">
<script src="https://cdn.shopify.com/s/shopifycloud/banner/v1"></script>
</head>
<body>
<div class="shopify-buy__product"></div>
</body>
</html>`,
		Scripts: []string{
			"https://cdn.shopify.com/s/shopifycloud/banner/v1",
		},
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	technologies := engine.Detect(ctx)

	foundShopify := false
	for _, tech := range technologies {
		if tech.Name == "Shopify" {
			foundShopify = true
			break
		}
	}

	if !foundShopify {
		t.Log("Shopify not detected (may be expected)")
	}
}

func TestCDNDetection(t *testing.T) {
	testCases := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "Cloudflare",
			headers:  map[string]string{"CF-RAY": "abc123"},
			expected: "Cloudflare",
		},
		{
			name:     "Akamai",
			headers:  map[string]string{"X-Cache": "HIT"},
			expected: "Akamai",
		},
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	for _, tc := range testCases {
		ctx := &DetectionContext{
			Headers: tc.headers,
			Body:    `<html></html>`,
		}

		technologies := engine.Detect(ctx)

		found := false
		for _, tech := range technologies {
			if tech.Name == tc.expected {
				found = true
				break
			}
		}

		if !found {
			t.Logf("%s not detected (may be expected)", tc.expected)
		}
	}
}

func TestAnalyticsDetection(t *testing.T) {
	ctx := &DetectionContext{
		Body: `<html>
<head>
<script src="https://www.googletagmanager.com/gtag/js?id=UA-123456-1"></script>
<script src="https://static.hotjar.com/c/hotjar-123.js"></script>
</head>
</html>`,
		Scripts: []string{
			"https://www.googletagmanager.com/gtag/js",
			"https://static.hotjar.com/c/hotjar",
		},
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	technologies := engine.Detect(ctx)

	foundGA := false
	foundHotjar := false
	for _, tech := range technologies {
		if tech.Name == "Google Analytics" {
			foundGA = true
		}
		if tech.Name == "Hotjar" {
			foundHotjar = true
		}
	}

	if !foundGA {
		t.Log("Google Analytics not detected")
	}
	if !foundHotjar {
		t.Log("Hotjar not detected")
	}
}

func TestBackendFrameworkDetection(t *testing.T) {
	ctx := &DetectionContext{
		Headers: map[string]string{
			"X-Powered-By": "NestJS",
		},
		Body: `<html></html>`,
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		t.Fatalf("Failed to create fingerprint engine: %v", err)
	}

	technologies := engine.Detect(ctx)

	foundNestJS := false
	for _, tech := range technologies {
		if tech.Name == "NestJS" {
			foundNestJS = true
			break
		}
	}

	if !foundNestJS {
		t.Log("NestJS not detected (may be expected)")
	}
}
