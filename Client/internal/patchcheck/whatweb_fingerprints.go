package patchcheck

func initWhatWebFingerprints() {
	whatWebDB := []WebFingerprint{
		{
			Name:     "Nginx",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nginx", Field: "Server"},
				{Type: "header", Value: "nginx", Field: "X-Powered-By"},
			},
			VersionRE: `nginx[/\s]?([\d.]+)`,
		},
		{
			Name:     "Apache",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "apache", Field: "Server"},
				{Type: "header", Value: "Apache", Field: "Server"},
				{Type: "html", Value: "It works!"},
				{Type: "html", Value: "Apache is functioning normally"},
			},
			VersionRE: `Apache[/\s]?([\d.]+)`,
		},
		{
			Name:     "Microsoft IIS",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "microsoft-iis", Field: "Server"},
				{Type: "header", Value: "ASP.NET", Field: "X-Powered-By"},
			},
			VersionRE: `Microsoft-IIS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Tomcat",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tomcat", Field: "Server"},
				{Type: "header", Value: "Apache-Coyote", Field: "Server"},
			},
			VersionRE: `Tomcat[/\s]?([\d.]+)`,
		},
		{
			Name:     "Jetty",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "jetty", Field: "Server"},
			},
			VersionRE: `Jetty[/\s]?([\d.]+)`,
		},
		{
			Name:     "Lighttpd",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "lighttpd", Field: "Server"},
			},
			VersionRE: `lighttpd[/\s]?([\d.]+)`,
		},
		{
			Name:     "Cherokee",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cherokee", Field: "Server"},
			},
			VersionRE: `Cherokee[/\s]?([\d.]+)`,
		},
		{
			Name:     "Caddy",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "caddy", Field: "Server"},
			},
			VersionRE: `Caddy[/\s]?([\d.]+)`,
		},
		{
			Name:     "OpenResty",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "openresty", Field: "Server"},
			},
			VersionRE: `openresty[/\s]?([\d.]+)`,
		},
		{
			Name:     "LiteSpeed",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "litespeed", Field: "Server"},
			},
			VersionRE: `LiteSpeed[/\s]?([\d.]+)`,
		},
		{
			Name:     "HAProxy",
			Category: "Load Balancer",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "haproxy", Field: "Server"},
			},
			VersionRE: `HAProxy[/\s]?([\d.]+)`,
		},
		{
			Name:     "Varnish",
			Category: "Cache Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "varnish", Field: "X-Varnish"},
				{Type: "header", Value: "varnish", Field: "Via"},
			},
			VersionRE: `varnish[/\s]?([\d.]+)`,
		},
		{
			Name:     "PHP",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "php", Field: "X-Powered-By"},
				{Type: "cookie", Value: "PHPSESSID"},
			},
			VersionRE: `PHP[/\s]?([\d.]+)`,
		},
		{
			Name:     "Python",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "python", Field: "X-Powered-By"},
				{Type: "header", Value: "werkzeug", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Ruby",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "ruby", Field: "X-Powered-By"},
			},
			VersionRE: `Ruby[/\s]?([\d.]+)`,
		},
		{
			Name:     "Perl",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "perl", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "ASP.NET",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "asp.net", Field: "X-Powered-By"},
				{Type: "header", Value: "ASP.NET", Field: "X-Powered-By"},
			},
			VersionRE: `ASP\.NET[/\s]?([\d.]+)`,
		},
		{
			Name:     "Java Servlet",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "servlet", Field: "X-Powered-By"},
				{Type: "header", Value: "JSP", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Node.js",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "node", Field: "X-Powered-By"},
				{Type: "header", Value: "express", Field: "X-Powered-By"},
			},
			VersionRE: `Node\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Rails",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rails", Field: "X-Powered-By"},
				{Type: "cookie", Value: "_rails"},
			},
			VersionRE: `Rails[/\s]?([\d.]+)`,
		},
		{
			Name:     "Django",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "django", Field: "X-Powered-By"},
				{Type: "html", Value: "csrfmiddlewaretoken"},
			},
			VersionRE: `Django[/\s]?([\d.]+)`,
		},
		{
			Name:     "Laravel",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "laravel", Field: "X-Powered-By"},
			},
			VersionRE: `Laravel[/\s]?([\d.]+)`,
		},
		{
			Name:     "CodeIgniter",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "codeigniter", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "ThinkPHP",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "thinkphp", Field: "X-Powered-By"},
			},
			VersionRE: `ThinkPHP[/\s]?([\d.]+)`,
		},
		{
			Name:     "Yii",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "yii", Field: "X-Powered-By"},
			},
			VersionRE: `Yii[/\s]?([\d.]+)`,
		},
		{
			Name:     "CakePHP",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cakephp", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Symfony",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "symfony", Field: "X-Powered-By"},
			},
			VersionRE: `Symfony[/\s]?([\d.]+)`,
		},
		{
			Name:     "Flask",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "werkzeug", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Express",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "express", Field: "X-Powered-By"},
			},
			VersionRE: `Express[/\s]?([\d.]+)`,
		},
		{
			Name:     "Koa",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "koa", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Spring",
			Category: "Java Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "spring", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Struts",
			Category: "Java Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "struts", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "jQuery",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jquery"},
				{Type: "html", Value: "jQuery"},
				{Type: "html", Value: "/jquery"},
				{Type: "html", Value: "jquery-ui"},
				{Type: "html", Value: "jquery.js"},
				{Type: "html", Value: "jquery.min.js"},
			},
			VersionRE: `jquery[/-]?([\d.]+)`,
		},
		{
			Name:     "Prototype",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prototype.js"},
				{Type: "html", Value: "prototype-"},
			},
			VersionRE: `prototype[/-]?([\d.]+)`,
		},
		{
			Name:     "MooTools",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mootools"},
				{Type: "html", Value: "mootools-core"},
			},
			VersionRE: `mootools[/\s]?([\d.]+)`,
		},
		{
			Name:     "Modernizr",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "modernizr"},
				{Type: "html", Value: "modernizr.js"},
			},
			VersionRE: `modernizr[/\s]?([\d.]+)`,
		},
		{
			Name:     "React",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "react"},
				{Type: "html", Value: "_reactRootContainer"},
			},
			VersionRE: `react[/\s]?([\d.]+)`,
		},
		{
			Name:     "Vue.js",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vue"},
				{Type: "html", Value: "__vue__"},
				{Type: "html", Value: "vue.js"},
			},
			VersionRE: `vue[/\s]?([\d.]+)`,
		},
		{
			Name:     "Angular",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "angular"},
				{Type: "html", Value: "ng-app"},
			},
			VersionRE: `angular[/\s]?([\d.]+)`,
		},
		{
			Name:     "Bootstrap",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bootstrap"},
				{Type: "html", Value: "bootstrap.min.css"},
				{Type: "html", Value: "bootstrap.js"},
			},
			VersionRE: `bootstrap[/\s]?([\d.]+)`,
		},
		{
			Name:     "Foundation",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "foundation"},
				{Type: "html", Value: "foundation.min.css"},
			},
			VersionRE: `foundation[/\s]?([\d.]+)`,
		},
		{
			Name:     "Tailwind CSS",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tailwindcss"},
			},
		},
		{
			Name:     "Handlebars",
			Category: "JavaScript Template",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "handlebars"},
				{Type: "html", Value: "x-handlebars-template"},
			},
			VersionRE: `handlebars[/\s]?([\d.]+)`,
		},
		{
			Name:     "WordPress",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wordpress"},
				{Type: "meta", Value: "wordpress"},
				{Type: "cookie", Value: "wordpress"},
				{Type: "header", Value: "wordpress", Field: "X-Powered-By"},
			},
			VersionRE: `WordPress[/\s]?([\d.]+)`,
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drupal"},
				{Type: "meta", Value: "drupal"},
				{Type: "cookie", Value: "drupal"},
			},
			VersionRE: `Drupal[/\s]?([\d.]+)`,
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "joomla"},
				{Type: "meta", Value: "joomla"},
				{Type: "cookie", Value: "joomla"},
			},
			VersionRE: `Joomla[/\s]?([\d.]+)`,
		},
		{
			Name:     "Magento",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "magento"},
				{Type: "cookie", Value: "magento"},
			},
			VersionRE: `Magento[/\s]?([\d.]+)`,
		},
		{
			Name:     "Shopify",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopify"},
				{Type: "header", Value: "shopify", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "OpenCart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "opencart"},
				{Type: "cookie", Value: "opencart"},
			},
		},
		{
			Name:     "PrestaShop",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prestashop"},
			},
			VersionRE: `PrestaShop[/\s]?([\d.]+)`,
		},
		{
			Name:     "WooCommerce",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "woocommerce"},
			},
		},
		{
			Name:     "phpBB",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "phpbb"},
				{Type: "cookie", Value: "phpbb"},
			},
			VersionRE: `phpBB[/\s]?([\d.]+)`,
		},
		{
			Name:     "vBulletin",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vbulletin"},
				{Type: "cookie", Value: "bb"},
			},
			VersionRE: `vBulletin[/\s]?([\d.]+)`,
		},
		{
			Name:     "Discuz",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discuz"},
				{Type: "html", Value: "comsenz"},
			},
		},
		{
			Name:     "Moodle",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "moodle"},
				{Type: "html", Value: "mod Moodle"},
				{Type: "header", Value: "moodle", Field: "X-Powered-By"},
			},
			VersionRE: `Moodle[/\s]?([\d.]+)`,
		},
		{
			Name:     "MediaWiki",
			Category: "Wiki",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mediawiki"},
				{Type: "cookie", Value: "mw"},
			},
			VersionRE: `MediaWiki[/\s]?([\d.]+)`,
		},
		{
			Name:     "DokuWiki",
			Category: "Wiki",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dokuwiki"},
				{Type: "cookie", Value: "DokuWiki"},
			},
		},
		{
			Name:     "Moodle",
			Category: "E-Learning",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "moodle"},
				{Type: "html", Value: "mod Moodle"},
			},
			VersionRE: `Moodle[/\s]?([\d.]+)`,
		},
		{
			Name:     "Cloudflare",
			Category: "CDN/WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cloudflare", Field: "Server"},
				{Type: "header", Value: "cf-ray", Field: ""},
			},
		},
		{
			Name:     "Akamai",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "akamai", Field: "Server"},
			},
		},
		{
			Name:     "Amazon CloudFront",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cloudfront", Field: "Via"},
			},
			VersionRE: `cloudfront[/\s]?([\d.]+)`,
		},
		{
			Name:     "CDN-Cache-Server",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cdn cache server", Field: "Server"},
				{Type: "header", Value: "cdn cache", Field: "X-Via"},
			},
			VersionRE: `CDN[/\s]?Cache[/\s]?Server[/\s]?V?([\d.]+)`,
		},
		{
			Name:     "X-Cache",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-cache", Field: ""},
			},
		},
		{
			Name:     "BWS",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "bws", Field: "Server"},
			},
			VersionRE: `BWS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Baidu",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "cookie", Value: "BAIDUID"},
				{Type: "cookie", Value: "BIDUPSID"},
				{Type: "cookie", Value: "PSTM"},
				{Type: "cookie", Value: "BDSVRTM"},
				{Type: "cookie", Value: "BD_HOME"},
			},
		},
		{
			Name:     "HTML5",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "<!DOCTYPE html"},
				{Type: "html", Value: "<!doctype html"},
			},
		},
		{
			Name:     "OpenSearch",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "opensearch"},
				{Type: "html", Value: "application/opensearchdescription+xml"},
			},
		},
		{
			Name:     "X-UA-Compatible",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-ua-compatible", Field: ""},
				{Type: "html", Value: "x-ua-compatible"},
			},
		},
		{
			Name:     "X-XSS-Protection",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-xss-protection", Field: ""},
			},
		},
		{
			Name:     "X-Content-Type-Options",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-content-type-options", Field: ""},
			},
		},
		{
			Name:     "Strict-Transport-Security",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "strict-transport-security", Field: ""},
			},
		},
		{
			Name:     "Content-Security-Policy",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "content-security-policy", Field: ""},
			},
		},
		{
			Name:     "X-Frame-Options",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-frame-options", Field: ""},
			},
		},
		{
			Name:     "Referrer-Policy",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "referrer-policy", Field: ""},
			},
		},
		{
			Name:     "WebSocket",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "upgrade", Field: ""},
			},
		},
		{
			Name:     "GZIP",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "gzip", Field: "Content-Encoding"},
			},
		},
		{
			Name:     "Deflate",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "deflate", Field: "Content-Encoding"},
			},
		},
		{
			Name:     "Vary",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vary", Field: ""},
			},
		},
		{
			Name:     "ETag",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "etag", Field: ""},
			},
		},
		{
			Name:     "Meta-Refresh",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<meta[^>]*http-equiv=["']?refresh["']?`},
			},
		},
		{
			Name:     "Favicon",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<link[^>]*rel=["']?icon["']?`},
				{Type: "html", Value: `<link[^>]*href=["']?[^>]*\.ico["']?`},
			},
		},
		{
			Name:     "PasswordField",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<input type="password"`},
				{Type: "html", Value: `type="password"`},
			},
		},
		{
			Name:     "Script",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<script`},
				{Type: "html", Value: `text/javascript`},
				{Type: "html", Value: `text/x-handlebars-template`},
			},
		},
		{
			Name:     "X-Via",
			Category: "Proxy Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-via", Field: ""},
			},
		},
		{
			Name:     "UncommonHeaders",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-ws-request-id", Field: ""},
			},
		},
		{
			Name:     "Google-Analytics",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "google-analytics.com"},
				{Type: "html", Value: "ga.js"},
				{Type: "html", Value: "gtag"},
			},
		},
		{
			Name:     "Baidu-Tongji",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hm.js"},
				{Type: "html", Value: "tongji.baidu.com"},
			},
		},
		{
			Name:     "CNZZ",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnzz.com"},
				{Type: "html", Value: "z5.cnzz.com"},
			},
		},
		{
			Name:     "Matomo",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "matomo"},
				{Type: "html", Value: "piwik"},
			},
		},
		{
			Name:     "Webpack",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webpack"},
				{Type: "html", Value: "webpack:///"},
			},
		},
		{
			Name:     "Babel",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "babel"},
			},
		},
		{
			Name:     "Font Awesome",
			Category: "CSS Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "font-awesome"},
				{Type: "html", Value: "fa-"},
			},
			VersionRE: `font-awesome[/\s]?([\d.]+)`,
		},
		{
			Name:     "Google Fonts",
			Category: "Web Font",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fonts.googleapis.com"},
			},
		},
		{
			Name:     "CDNJS",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cdnjs.cloudflare.com"},
			},
		},
		{
			Name:     "jsDelivr",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cdn.jsdelivr.net"},
			},
		},
		{
			Name:     "Unpkg",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "unpkg.com"},
			},
		},
		{
			Name:     "Gravatar",
			Category: "Web Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gravatar.com"},
				{Type: "html", Value: "secure.gravatar.com"},
			},
		},
		{
			Name:     "AddThis",
			Category: "Social Widget",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "addthis"},
				{Type: "html", Value: "addthis.com"},
			},
		},
		{
			Name:     "ShareThis",
			Category: "Social Widget",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sharethis"},
				{Type: "html", Value: "sharethis.com"},
			},
		},
		{
			Name:     "Disqus",
			Category: "Comment System",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "disqus"},
				{Type: "html", Value: "disqus.com"},
			},
		},
		{
			Name:     "Facebook",
			Category: "Social Widget",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "connect.facebook.net"},
				{Type: "html", Value: "fb-root"},
			},
		},
		{
			Name:     "Twitter Widget",
			Category: "Social Widget",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "platform.twitter.com"},
				{Type: "html", Value: "twitter-wjs"},
			},
		},
		{
			Name:     "LinkedIn",
			Category: "Social Widget",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "platform.linkedin.com"},
			},
		},
		{
			Name:     "YouTube",
			Category: "Video Player",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "youtube.com"},
				{Type: "html", Value: "youtube-nocookie.com"},
			},
		},
		{
			Name:     "Vimeo",
			Category: "Video Player",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vimeo.com"},
				{Type: "html", Value: "player.vimeo.com"},
			},
		},
		{
			Name:     "JW Player",
			Category: "Video Player",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jwplayer"},
				{Type: "html", Value: "jw-platform.com"},
			},
			VersionRE: `jwplayer[/\s]?([\d.]+)`,
		},
		{
			Name:     "Video.js",
			Category: "Video Player",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "video.js"},
				{Type: "html", Value: "vjs-"},
			},
		},
		{
			Name:     "PayPal",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paypal"},
				{Type: "html", Value: "paypal.com"},
			},
		},
		{
			Name:     "Stripe",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stripe"},
				{Type: "html", Value: "js.stripe.com"},
			},
		},
		{
			Name:     "Alipay",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alipay"},
				{Type: "html", Value: "alipay.com"},
			},
		},
		{
			Name:     "WeChat",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weixin"},
				{Type: "html", Value: "wxpay"},
			},
		},
		{
			Name:     "reCAPTCHA",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "recaptcha"},
				{Type: "html", Value: "google.com/recaptcha"},
			},
			VersionRE: `reCAPTCHA[/\s]?([\d.]+)`,
		},
		{
			Name:     "Cloudflare Turnstile",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "challenges.cloudflare.com"},
				{Type: "html", Value: "turnstile"},
			},
		},
		{
			Name:     "Sucuri",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sucuri", Field: "X-Sucuri-ID"},
			},
		},
		{
			Name:     "ModSecurity",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mod_security", Field: "Server"},
				{Type: "header", Value: "modsecurity", Field: "X-ModSecurity"},
			},
		},
		{
			Name:     "WebKnight",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "webknight", Field: "Server"},
			},
		},
		{
			Name:     "DotDefender",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "dotdefender", Field: "X-Engine"},
			},
		},
		{
			Name:     "SafeDog",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "safedog", Field: "Server"},
			},
		},
		{
			Name:     "OpenSSL",
			Category: "SSL/TLS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "openssl", Field: "Server"},
			},
			VersionRE: `OpenSSL[/\s]?([\d.]+)`,
		},
		{
			Name:     "TLS",
			Category: "SSL/TLS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tls", Field: "Upgrade"},
			},
		},
		{
			Name:     "HTTP/2",
			Category: "Protocol",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "http/2", Field: ""},
				{Type: "header", Value: "h2", Field: ""},
			},
		},
		{
			Name:     "HTTP/3",
			Category: "Protocol",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "http/3", Field: ""},
				{Type: "header", Value: "h3", Field: ""},
			},
		},
		{
			Name:     "WebDAV",
			Category: "Protocol",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "webdav", Field: "Server"},
				{Type: "header", Value: "DAV", Field: ""},
			},
		},
		{
			Name:     "HTTPOnly",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "httponly", Field: ""},
			},
		},
		{
			Name:     "SameSite",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "samesite", Field: ""},
			},
		},
		{
			Name:     "P3P",
			Category: "Privacy Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "p3p", Field: ""},
			},
		},
		{
			Name:     "Rails",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rails", Field: "X-Powered-By"},
			},
			VersionRE: `Rails[/\s]?([\d.]+)`,
		},
		{
			Name:     "Passenger",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "passenger", Field: "X-Powered-By"},
			},
			VersionRE: `Passenger[/\s]?([\d.]+)`,
		},
		{
			Name:     "Phusion Passenger",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "passenger", Field: "Server"},
			},
			VersionRE: `Passenger[/\s]?([\d.]+)`,
		},
		{
			Name:     "Puma",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "puma", Field: "Server"},
			},
			VersionRE: `Puma[/\s]?([\d.]+)`,
		},
		{
			Name:     "Unicorn",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "unicorn", Field: "Server"},
			},
		},
		{
			Name:     "Thin",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "thin", Field: "Server"},
			},
		},
		{
			Name:     "Gunicorn",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "gunicorn", Field: "Server"},
			},
			VersionRE: `gunicorn[/\s]?([\d.]+)`,
		},
		{
			Name:     "uWSGI",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "uwsgi", Field: "Server"},
				{Type: "header", Value: "uwsgi", Field: "X-Uwsgi-By"},
			},
		},
		{
			Name:     "Resin",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "resin", Field: "Server"},
			},
			VersionRE: `Resin[/\s]?([\d.]+)`,
		},
		{
			Name:     "JBoss",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "jboss", Field: "Server"},
			},
			VersionRE: `JBoss[/\s]?([\d.]+)`,
		},
		{
			Name:     "WildFly",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "wildfly", Field: "Server"},
			},
			VersionRE: `WildFly[/\s]?([\d.]+)`,
		},
		{
			Name:     "GlassFish",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "glassfish", Field: "Server"},
			},
		},
		{
			Name:     "WebLogic",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "weblogic", Field: "Server"},
				{Type: "header", Value: "WebLogic", Field: "X-Powered-By"},
			},
			VersionRE: `WebLogic[/\s]?([\d.]+)`,
		},
		{
			Name:     "WebSphere",
			Category: "App Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "websphere", Field: "Server"},
			},
		},
		{
			Name:     "TongWen",
			Category: "Chinese Encoding",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tongwen", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Ecshop",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ecshop"},
			},
		},
		{
			Name:     "ShopEx",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopex"},
			},
		},
		{
			Name:     "ECMall",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ecmall"},
			},
		},
		{
			Name:     "HiShop",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hishop"},
			},
		},
		{
			Name:     "KingCart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kingcart"},
			},
		},
		{
			Name:     "Cscart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cscart"},
			},
		},
		{
			Name:     "Zeuscart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zeuscart"},
			},
		},
		{
			Name:     "osCommerce",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "oscommerce"},
			},
		},
		{
			Name:     "CubeCart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cubecart"},
			},
		},
		{
			Name:     "VirtueMart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "virtuemart"},
			},
		},
		{
			Name:     "SunOS",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sunos", Field: "Server"},
			},
		},
		{
			Name:     "FreeBSD",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "freebsd", Field: "Server"},
			},
		},
		{
			Name:     "AIX",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "aix", Field: "Server"},
			},
		},
		{
			Name:     "HP-UX",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hp-ux", Field: "Server"},
			},
		},
		{
			Name:     "IRIX",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "irix", Field: "Server"},
			},
		},
		{
			Name:     "Tru64",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tru64", Field: "Server"},
			},
		},
		{
			Name:     "Windows",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "windows", Field: "Server"},
			},
		},
		{
			Name:     "Linux",
			Category: "OS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "linux", Field: "Server"},
			},
		},
		{
			Name:     "Gunicorn",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "gunicorn", Field: "Server"},
			},
			VersionRE: `gunicorn[/\s]?([\d.]+)`,
		},
		{
			Name:     "Phusion Passenger",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "passenger", Field: "X-Powered-By"},
				{Type: "header", Value: "passenger", Field: "Server"},
			},
			VersionRE: `Phusion\s*Passenger[/\s]?([\d.]+)`,
		},
		{
			Name:     "Puma",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "puma", Field: "Server"},
			},
			VersionRE: `puma[/\s]?([\d.]+)`,
		},
		{
			Name:     "Thin",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "thin", Field: "Server"},
			},
			VersionRE: `Thin[/\s]?([\d.]+)`,
		},
		{
			Name:     "Resin",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "resin", Field: "Server"},
			},
			VersionRE: `Resin[/\s]?([\d.]+)`,
		},
		{
			Name:     "IBM WebSphere",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "websphere", Field: "Server"},
				{Type: "header", Value: "IBM", Field: "Server"},
			},
			VersionRE: `WebSphere[/\s]?([\d.]+)`,
		},
		{
			Name:     "Oracle Application Server",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "oracle", Field: "Server"},
				{Type: "header", Value: "oracle-application-server", Field: "Server"},
			},
		},
		{
			Name:     "Sun ONE Web Server",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sun-one", Field: "Server"},
				{Type: "header", Value: "sun-one-web-server", Field: "Server"},
			},
		},
		{
			Name:     "Zeus",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "zeus", Field: "Server"},
			},
			VersionRE: `Zeus[/\s]?([\d.]+)`,
		},
		{
			Name:     "Kangle",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "kangle", Field: "Server"},
			},
		},
		{
			Name:     "Tornado",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tornado", Field: "Server"},
			},
			VersionRE: `TornadoServer[/\s]?([\d.]+)`,
		},
		{
			Name:     "AJP",
			Category: "Protocol",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "ajp", Field: "Server"},
			},
		},
		{
			Name:     "WordPress",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wp-content"},
				{Type: "html", Value: "wp-includes"},
				{Type: "html", Value: "wordpress"},
				{Type: "header", Value: "wordpress", Field: "X-Powered-By"},
			},
			VersionRE: `WordPress[/\s]?([\d.]+)`,
		},
		{
			Name:     "WordPress MU",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wpmu"},
				{Type: "html", Value: "wordpress-mu"},
			},
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "joomla"},
				{Type: "header", Value: "joomla", Field: "X-Powered-By"},
			},
			VersionRE: `Joomla![/\s]?([\d.]+)`,
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drupal"},
				{Type: "html", Value: "Drupal.settings"},
				{Type: "header", Value: "drupal", Field: "X-Powered-By"},
			},
			VersionRE: `Drupal[/\s]?([\d.]+)`,
		},
		{
			Name:     "Magento",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "Mage.Cookies"},
				{Type: "html", Value: "magento"},
				{Type: "html", Value: "varien/form"},
			},
			VersionRE: `Magento[/\s]?([\d.]+)`,
		},
		{
			Name:     "Shopify",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "shopify", Field: "X-Shopify-Stage"},
				{Type: "html", Value: "shopify"},
			},
		},
		{
			Name:     "OpenCart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "opencart"},
				{Type: "html", Value: "index.php?route=common/home"},
			},
			VersionRE: `OpenCart[/\s]?([\d.]+)`,
		},
		{
			Name:     "PrestaShop",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prestashop"},
				{Type: "html", Value: "PrestaShop"},
			},
			VersionRE: `PrestaShop[/\s]?([\d.]+)`,
		},
		{
			Name:     "WooCommerce",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "woocommerce"},
				{Type: "html", Value: "woo_variation_select"},
			},
		},
		{
			Name:     "ECShop",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ecshop"},
				{Type: "html", Value: "ECSHOP"},
			},
		},
		{
			Name:     "Shopex",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopex"},
				{Type: "html", Value: "ShopEx"},
			},
		},
		{
			Name:     "phpCMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "phpcms"},
				{Type: "html", Value: "PHPCMS"},
			},
		},
		{
			Name:     "帝国CMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "empirecms"},
				{Type: "html", Value: "EmpireCMS"},
			},
		},
		{
			Name:     "Dedecms",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dedecms"},
				{Type: "html", Value: "DedeCms"},
				{Type: "html", Value: "dedeajax"},
			},
			VersionRE: `DedeCms[/\s]?([\d.]+)`,
		},
		{
			Name:     "MetInfo",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "metinfo"},
				{Type: "html", Value: "MetInfo"},
			},
		},
		{
			Name:     "SiteServer CMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "siteserver"},
				{Type: "html", Value: "SiteServer"},
			},
		},
		{
			Name:     "Typecho",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "typecho"},
				{Type: "header", Value: "typecho", Field: "X-Powered-By"},
			},
			VersionRE: `Typecho[/\s]?([\d.]+)`,
		},
		{
			Name:     "Z-Blog",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "z-blog"},
				{Type: "html", Value: "Z-Blog"},
				{Type: "header", Value: "z-blog", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "WordPress.com",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "wordpress.com", Field: "X-Hacker"},
			},
		},
		{
			Name:     "Blogger",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blogger"},
				{Type: "html", Value: "blogspot"},
			},
		},
		{
			Name:     "Wiki.js",
			Category: "Wiki",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wikijs"},
				{Type: "header", Value: "wiki", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Confluence",
			Category: "Wiki",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "confluence"},
				{Type: "header", Value: "confluence", Field: "X-Confluence-Request-Time"},
			},
		},
		{
			Name:     "Jira",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jira"},
				{Type: "html", Value: "atlassian"},
			},
		},
		{
			Name:     "Redmine",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "redmine"},
				{Type: "html", Value: "Redmine"},
			},
		},
		{
			Name:     "Trac",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trac"},
				{Type: "html", Value: "Trac"},
			},
		},
		{
			Name:     "Moodle",
			Category: "E-Learning",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "moodle"},
				{Type: "html", Value: "Moodle"},
			},
			VersionRE: `Moodle[/\s]?([\d.]+)`,
		},
		{
			Name:     "Canvas LMS",
			Category: "E-Learning",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "canvas"},
				{Type: "html", Value: "canvas-lms"},
			},
		},
		{
			Name:     "DokuWiki",
			Category: "Wiki",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dokuwiki"},
				{Type: "html", Value: "DokuWiki"},
			},
			VersionRE: `DokuWiki[/\s]?([\d.]+)`,
		},
		{
			Name:     "MediaWiki",
			Category: "Wiki",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mediawiki"},
				{Type: "html", Value: "MediaWiki"},
			},
			VersionRE: `MediaWiki[/\s]?([\d.]+)`,
		},
		{
			Name:     "phpBB",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "phpbb"},
				{Type: "header", Value: "phpbb", Field: "X-Powered-By"},
			},
			VersionRE: `phpBB[/\s]?([\d.]+)`,
		},
		{
			Name:     "vBulletin",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vbulletin"},
				{Type: "header", Value: "vbulletin", Field: "X-Powered-By"},
			},
			VersionRE: `vBulletin[/\s]?([\d.]+)`,
		},
		{
			Name:     "Discuz",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discuz"},
				{Type: "html", Value: "Discuz"},
				{Type: "html", Value: "DZ"},
			},
		},
		{
			Name:     "XenForo",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xenforo"},
				{Type: "html", Value: "XenForo"},
			},
		},
		{
			Name:     "Flarum",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "flarum"},
			},
		},
		{
			Name:     "NodeBB",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nodebb"},
			},
		},
		{
			Name:     "Discourse",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discourse"},
			},
		},
		{
			Name:     "jQuery",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jquery"},
				{Type: "html", Value: "jQuery"},
			},
			VersionRE: `jQuery[/\s]?([\d.]+)`,
		},
		{
			Name:     "jQuery UI",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jquery-ui"},
				{Type: "html", Value: "jqueryui"},
			},
			VersionRE: `jQuery\s+UI[/\s]?([\d.]+)`,
		},
		{
			Name:     "Prototype",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prototype"},
				{Type: "html", Value: "Prototype"},
			},
			VersionRE: `Prototype[/\s]?([\d.]+)`,
		},
		{
			Name:     "MooTools",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mootools"},
				{Type: "html", Value: "MooTools"},
			},
			VersionRE: `MooTools[/\s]?([\d.]+)`,
		},
		{
			Name:     "Dojo Toolkit",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dojo"},
				{Type: "html", Value: "Dojo"},
			},
			VersionRE: `Dojo[/\s]?([\d.]+)`,
		},
		{
			Name:     "Ext JS",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "extjs"},
				{Type: "html", Value: "Ext"},
			},
			VersionRE: `Ext\s+JS[/\s]?([\d.]+)`,
		},
		{
			Name:     "YUI",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yui"},
				{Type: "html", Value: "YUI"},
			},
			VersionRE: `YUI[/\s]?([\d.]+)`,
		},
		{
			Name:     "Underscore.js",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "underscore"},
			},
			VersionRE: `Underscore\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Lodash",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lodash"},
			},
			VersionRE: `lodash[/\s]?([\d.]+)`,
		},
		{
			Name:     "Moment.js",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "moment"},
			},
			VersionRE: `momentjs[/\s]?([\d.]+)`,
		},
		{
			Name:     "Vue.js",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vue"},
				{Type: "html", Value: "data-v-"},
			},
			VersionRE: `Vue[/\s]?([\d.]+)`,
		},
		{
			Name:     "React",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "react"},
				{Type: "html", Value: "_reactRootContainer"},
			},
			VersionRE: `React[/\s]?([\d.]+)`,
		},
		{
			Name:     "Angular",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "angular"},
				{Type: "html", Value: "ng-version"},
			},
			VersionRE: `Angular[/\s]?([\d.]+)`,
		},
		{
			Name:     "AngularJS",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ng-app"},
				{Type: "html", Value: "angular.js"},
				{Type: "html", Value: "angular.module"},
			},
			VersionRE: `AngularJS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Backbone.js",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "backbone"},
			},
			VersionRE: `Backbone[/\s]?([\d.]+)`,
		},
		{
			Name:     "Ember.js",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ember"},
				{Type: "html", Value: "ember-data"},
			},
			VersionRE: `Ember\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Svelte",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "svelte"},
			},
			VersionRE: `Svelte[/\s]?([\d.]+)`,
		},
		{
			Name:     "Preact",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "preact"},
			},
			VersionRE: `Preact[/\s]?([\d.]+)`,
		},
		{
			Name:     "Alpine.js",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alpinejs"},
			},
		},
		{
			Name:     "Semantic UI",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "semantic"},
				{Type: "html", Value: "semantic-ui"},
			},
			VersionRE: `Semantic-UI[/\s]?([\d.]+)`,
		},
		{
			Name:     "Bulma",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bulma"},
			},
			VersionRE: `bulma[/\s]?([\d.]+)`,
		},
		{
			Name:     "Vuetify",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vuetify"},
			},
			VersionRE: `Vuetify[/\s]?([\d.]+)`,
		},
		{
			Name:     "Element UI",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "element-ui"},
				{Type: "html", Value: "el-container"},
			},
			VersionRE: `Element[/\s]?([\d.]+)`,
		},
		{
			Name:     "Ant Design",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ant-design"},
				{Type: "html", Value: "ant-layout"},
			},
			VersionRE: `Ant\s+Design[/\s]?([\d.]+)`,
		},
		{
			Name:     "Layui",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "layui"},
				{Type: "html", Value: "layer"},
			},
		},
		{
			Name:     "EasyUI",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jquery-easyui"},
				{Type: "html", Value: "easyui"},
			},
		},
		{
			Name:     "WeUI",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weui"},
			},
		},
		{
			Name:     "Mint UI",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mint-ui"},
			},
		},
		{
			Name:     "Vant",
			Category: "UI Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vant"},
				{Type: "html", Value: "van-"},
			},
			VersionRE: `Vant[/\s]?([\d.]+)`,
		},
		{
			Name:     "SWR",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "swr"},
			},
		},
		{
			Name:     "Axios",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "axios"},
			},
			VersionRE: `axios[/\s]?([\d.]+)`,
		},
		{
			Name:     "Chart.js",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chart.js"},
				{Type: "html", Value: "Chart"},
			},
			VersionRE: `Chart\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "ECharts",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "echarts"},
				{Type: "html", Value: "echarts.js"},
			},
			VersionRE: `ECharts[/\s]?([\d.]+)`,
		},
		{
			Name:     "Highcharts",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "highcharts"},
				{Type: "html", Value: "Highcharts"},
			},
			VersionRE: `Highcharts[/\s]?([\d.]+)`,
		},
		{
			Name:     "D3.js",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "d3.js"},
				{Type: "html", Value: "d3.v"},
			},
			VersionRE: `d3[/\s]?([\d.]+)`,
		},
		{
			Name:     "Three.js",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "three.js"},
				{Type: "html", Value: "three.min"},
			},
			VersionRE: `three[/\s]?([\d.]+)`,
		},
		{
			Name:     "Swiper",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "swiper"},
			},
			VersionRE: `Swiper[/\s]?([\d.]+)`,
		},
		{
			Name:     "Slick",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "slick"},
			},
			VersionRE: `Slick[/\s]?([\d.]+)`,
		},
		{
			Name:     "Modernizr",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "modernizr"},
			},
			VersionRE: `Modernizr[/\s]?([\d.]+)`,
		},
		{
			Name:     "Polyfill",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "polyfill"},
			},
		},
		{
			Name:     "Core JS",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "core-js"},
			},
		},
		{
			Name:     "Babel",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "babel"},
			},
		},
		{
			Name:     "Webpack",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webpack"},
			},
			VersionRE: `webpack[/\s]?([\d.]+)`,
		},
		{
			Name:     "Vite",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vite"},
			},
		},
		{
			Name:     "Gulp",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gulp"},
			},
		},
		{
			Name:     "Grunt",
			Category: "Build Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "grunt"},
			},
		},
		{
			Name:     "Bootstrap",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bootstrap"},
			},
			VersionRE: `Bootstrap[/\s]?([\d.]+)`,
		},
		{
			Name:     "Foundation",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "foundation"},
			},
			VersionRE: `Foundation[/\s]?([\d.]+)`,
		},
		{
			Name:     "Materialize",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "materialize"},
			},
			VersionRE: `Materialize[/\s]?([\d.]+)`,
		},
		{
			Name:     "UIKit",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uikit"},
			},
			VersionRE: `UIKit[/\s]?([\d.]+)`,
		},
		{
			Name:     "Tailwind CSS",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tailwindcss"},
				{Type: "html", Value: "tailwind"},
			},
			VersionRE: `TailwindCSS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Less",
			Category: "CSS Preprocessor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "less"},
			},
			VersionRE: `less[/\s]?([\d.]+)`,
		},
		{
			Name:     "Sass",
			Category: "CSS Preprocessor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sass"},
				{Type: "html", Value: "scss"},
			},
			VersionRE: `Sass[/\s]?([\d.]+)`,
		},
		{
			Name:     "Stylus",
			Category: "CSS Preprocessor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stylus"},
			},
		},
		{
			Name:     "Google Fonts",
			Category: "Font",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fonts.googleapis"},
				{Type: "html", Value: "fonts.gstatic"},
			},
		},
		{
			Name:     "Font Awesome",
			Category: "Icon Font",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "font-awesome"},
				{Type: "html", Value: "fontawesome"},
			},
			VersionRE: `Font\s+Awesome[/\s]?([\d.]+)`,
		},
		{
			Name:     "Ionicons",
			Category: "Icon Font",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ionicons"},
			},
			VersionRE: `Ionicons[/\s]?([\d.]+)`,
		},
		{
			Name:     "Material Icons",
			Category: "Icon Font",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "material-icons"},
			},
		},
		{
			Name:     "Google Analytics",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "google-analytics"},
				{Type: "html", Value: "ga.js"},
				{Type: "html", Value: "gtag"},
			},
		},
		{
			Name:     "Google Tag Manager",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "googletagmanager"},
			},
		},
		{
			Name:     "Baidu Tongji",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hm.js"},
				{Type: "html", Value: "baidu"},
			},
		},
		{
			Name:     "CNZZ",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnzz"},
				{Type: "html", Value: "z_stat"},
			},
		},
		{
			Name:     "Matomo",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "matomo"},
			},
			VersionRE: `Matomo[/\s]?([\d.]+)`,
		},
		{
			Name:     "Hotjar",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hotjar"},
			},
		},
		{
			Name:     "Mixpanel",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mixpanel"},
			},
		},
		{
			Name:     "HubSpot",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hs-scripts"},
				{Type: "html", Value: "hubspot"},
			},
		},
		{
			Name:     "Crazy Egg",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "crazyegg"},
			},
		},
		{
			Name:     "Cloudflare",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cloudflare", Field: "Server"},
				{Type: "header", Value: "cf-ray", Field: ""},
			},
		},
		{
			Name:     "CloudFront",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cloudfront", Field: "Server"},
			},
			VersionRE: `cloudfront[/\s]?([\d.]+)`,
		},
		{
			Name:     "Akamai",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "akamai", Field: "Server"},
				{Type: "header", Value: "akamaihd", Field: "Server"},
			},
		},
		{
			Name:     "Fastly",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fastly", Field: "Server"},
			},
		},
		{
			Name:     "Aliyun OSS",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "aliyun", Field: "Server"},
				{Type: "header", Value: "aliyuncs", Field: "Server"},
			},
		},
		{
			Name:     "Qiniu",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "qiniu", Field: "Server"},
			},
		},
		{
			Name:     "腾讯云",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tencent", Field: "Server"},
			},
		},
		{
			Name:     "Upyun",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "upai", Field: "Server"},
			},
		},
		{
			Name:     "Vercel",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vercel", Field: "X-Vercel-Cache"},
			},
		},
		{
			Name:     "Netlify",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "netlify", Field: "X-NF-Cache-Status"},
			},
		},
		{
			Name:     "Render",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "render", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Heroku",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "heroku", Field: "X-Heroku-Handled-By"},
			},
		},
		{
			Name:     "Surge.sh",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "surge.sh", Field: "Server"},
			},
		},
		{
			Name:     "GitHub Pages",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "github.io", Field: "Server"},
			},
		},
		{
			Name:     "AWS Elastic Beanstalk",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "aws-elastic-beanstalk", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "PHP",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "php", Field: "X-Powered-By"},
			},
			VersionRE: `PHP[/\s]?([\d.]+)`,
		},
		{
			Name:     "Python",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "python", Field: "X-Powered-By"},
			},
			VersionRE: `Python[/\s]?([\d.]+)`,
		},
		{
			Name:     "Ruby",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "ruby", Field: "X-Powered-By"},
			},
			VersionRE: `Ruby[/\s]?([\d.]+)`,
		},
		{
			Name:     "Perl",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "perl", Field: "X-Powered-By"},
			},
			VersionRE: `Perl[/\s]?([\d.]+)`,
		},
		{
			Name:     "ASP.NET",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "asp.net", Field: "X-Powered-By"},
				{Type: "header", Value: "ASP.NET", Field: "X-Powered-By"},
			},
			VersionRE: `ASP\.NET[/\s]?([\d.]+)`,
		},
		{
			Name:     "Zend Framework",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "zend", Field: "X-Powered-By"},
			},
			VersionRE: `Zend[/\s]?([\d.]+)`,
		},
		{
			Name:     "Phalcon",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "phalcon", Field: "X-Powered-By"},
			},
			VersionRE: `Phalcon[/\s]?([\d.]+)`,
		},
		{
			Name:     "Yaf",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "yaf", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Swoole",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "swoole", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Slim",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "slim", Field: "X-Powered-By"},
			},
			VersionRE: `Slim[/\s]?([\d.]+)`,
		},
		{
			Name:     "Silex",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "silex", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Lumen",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "lumen", Field: "X-Powered-By"},
			},
			VersionRE: `Lumen[/\s]?([\d.]+)`,
		},
		{
			Name:     "Golang",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "go", Field: "X-Powered-By"},
			},
			VersionRE: `Go[/\s]?([\d.]+)`,
		},
		{
			Name:     "Rust",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rust", Field: "X-Powered-By"},
			},
			VersionRE: `Rust[/\s]?([\d.]+)`,
		},
		{
			Name:     "Rocket",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rocket", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Actix",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "actix", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Gin",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "gin", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Echo",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "echo", Field: "X-Powered-By"},
			},
			VersionRE: `Echo[/\s]?([\d.]+)`,
		},
		{
			Name:     "Fiber",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fiber", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Phoenix",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "phoenix", Field: "X-Powered-By"},
			},
			VersionRE: `Phoenix[/\s]?([\d.]+)`,
		},
		{
			Name:     "Spring",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "spring", Field: "X-Powered-By"},
			},
			VersionRE: `Spring[/\s]?([\d.]+)`,
		},
		{
			Name:     "Struts",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "struts", Field: "X-Powered-By"},
			},
			VersionRE: `Struts[/\s]?([\d.]+)`,
		},
		{
			Name:     "Hibernate",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hibernate", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "MyBatis",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mybatis", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "TypeORM",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "typeorm", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Sequelize",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sequelize", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Prisma",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "prisma", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Swagger",
			Category: "API Documentation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "swagger"},
				{Type: "html", Value: "swagger-ui"},
			},
		},
		{
			Name:     "OpenAPI",
			Category: "API Documentation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "openapi"},
				{Type: "html", Value: "swagger"},
			},
		},
		{
			Name:     "GraphQL",
			Category: "API",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "graphql"},
				{Type: "header", Value: "graphql", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Apollo",
			Category: "GraphQL",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apollo"},
				{Type: "html", Value: "apollo-client"},
			},
		},
		{
			Name:     "Apollo Server",
			Category: "GraphQL",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "apollo-server", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "REST API",
			Category: "API",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rest", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Socket.IO",
			Category: "Real-time Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "socket.io"},
				{Type: "header", Value: "socket.io", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "WebSocket",
			Category: "Real-time Communication",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "websocket", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "SignalR",
			Category: "Real-time Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "signalr"},
			},
		},
		{
			Name:     "ModSecurity",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "modsecurity", Field: "X-CRS-Version"},
				{Type: "header", Value: "mod_security", Field: "Server"},
			},
		},
		{
			Name:     "ModSecurity WAF",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "modsecurity", Field: "Server"},
			},
		},
		{
			Name:     "AWS WAF",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "aws-waf", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "OWASP ModSecurity Core Rule Set",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "OWASP_CRS", Field: "X-CRS-Version"},
			},
		},
		{
			Name:     "F5 BIG-IP ASM",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "bigip", Field: "Server"},
				{Type: "header", Value: "BIG-IP", Field: "Server"},
			},
		},
		{
			Name:     "Imperva SecureSphere",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "imperva", Field: "Server"},
			},
		},
		{
			Name:     "FortiWeb",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fortiweb", Field: "Server"},
			},
		},
		{
			Name:     "DenyAll",
			Category: "WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "denyall", Field: "Server"},
			},
		},
		{
			Name:     "SQL Injection Protection",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "SQL", Field: "X-Blocked-By"},
			},
		},
		{
			Name:     "XSS Protection",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-XSS-Protection", Field: ""},
			},
		},
		{
			Name:     "HSTS",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Strict-Transport-Security", Field: ""},
			},
		},
		{
			Name:     "Content Security Policy",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Content-Security-Policy", Field: ""},
			},
		},
		{
			Name:     "X-Frame-Options",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Frame-Options", Field: ""},
			},
		},
		{
			Name:     "X-Content-Type-Options",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Content-Type-Options", Field: ""},
			},
		},
		{
			Name:     "Referrer-Policy",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Referrer-Policy", Field: ""},
			},
		},
		{
			Name:     "Permissions-Policy",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Permissions-Policy", Field: ""},
			},
		},
		{
			Name:     "SameSite",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "SameSite", Field: ""},
			},
		},
		{
			Name:     "Adobe Experience Manager",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aem"},
				{Type: "html", Value: "Adobe Experience Manager"},
			},
		},
		{
			Name:     "Sitecore",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sitecore"},
				{Type: "html", Value: "Sitecore"},
			},
		},
		{
			Name:     "Umbraco",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "umbraco"},
				{Type: "header", Value: "umbraco", Field: "X-Powered-By"},
			},
			VersionRE: `Umbraco[/\s]?([\d.]+)`,
		},
		{
			Name:     "Episerver",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "episerver"},
				{Type: "html", Value: "EPiServer"},
			},
		},
		{
			Name:     "Kentico",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kentico"},
			},
		},
		{
			Name:     "Webflow",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webflow"},
			},
		},
		{
			Name:     "Squarespace",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "squarespace"},
			},
		},
		{
			Name:     "Wix",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wix"},
			},
		},
		{
			Name:     "Weebly",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weebly"},
			},
		},
		{
			Name:     "Ghost",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ghost"},
			},
			VersionRE: `Ghost[/\s]?([\d.]+)`,
		},
		{
			Name:     "Hexo",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hexo"},
			},
			VersionRE: `Hexo[/\s]?([\d.]+)`,
		},
		{
			Name:     "Hugo",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hugo"},
			},
			VersionRE: `Hugo[/\s]?([\d.]+)`,
		},
		{
			Name:     "Jekyll",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jekyll"},
			},
			VersionRE: `Jekyll[/\s]?([\d.]+)`,
		},
		{
			Name:     "Pelican",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pelican"},
			},
			VersionRE: `Pelican[/\s]?([\d.]+)`,
		},
		{
			Name:     "Gatsby",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gatsby"},
			},
			VersionRE: `Gatsby[/\s]?([\d.]+)`,
		},
		{
			Name:     "Next.js",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "next"},
				{Type: "html", Value: "__NEXT"},
			},
			VersionRE: `Next\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Nuxt.js",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nuxt"},
				{Type: "html", Value: "__NUXT"},
			},
			VersionRE: `Nuxt[/\s]?([\d.]+)`,
		},
		{
			Name:     "Docusaurus",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "docusaurus"},
			},
			VersionRE: `Docusaurus[/\s]?([\d.]+)`,
		},
		{
			Name:     "VitePress",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vitepress"},
			},
		},
		{
			Name:     "Astro",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "astro"},
			},
			VersionRE: `Astro[/\s]?([\d.]+)`,
		},
		{
			Name:     "Scully",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "scully"},
			},
		},
		{
			Name:     "Eleventy",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "eleventy"},
			},
		},
		{
			Name:     "Gridsome",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gridsome"},
			},
		},
		{
			Name:     "VuePress",
			Category: "Static Site Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vuepress"},
			},
			VersionRE: `VuePress[/\s]?([\d.]+)`,
		},
		{
			Name:     "Docpress",
			Category: "Documentation Generator",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "docpress"},
			},
		},
		{
			Name:     "Stripe",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "js.stripe.com"},
			},
		},
		{
			Name:     "PayPal",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paypal"},
				{Type: "html", Value: "www.paypal.com"},
			},
		},
		{
			Name:     "Alipay",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alipay"},
				{Type: "html", Value: "alipay.com"},
			},
		},
		{
			Name:     "WeChat Pay",
			Category: "Payment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weixin"},
				{Type: "html", Value: "wechat"},
			},
		},
		{
			Name:     "Cloudflare Rocket Loader",
			Category: "Performance",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rocketloader", Field: "X-Content-Type-Options"},
			},
		},
		{
			Name:     "Google PageSpeed",
			Category: "Performance",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "pagespeed", Field: "X-Page-Speed"},
			},
			VersionRE: `PageSpeed[/\s]?([\d.]+)`,
		},
		{
			Name:     "Compressor",
			Category: "Performance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "compressor"},
			},
		},
		{
			Name:     "AMP",
			Category: "Mobile",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ampproject"},
				{Type: "html", Value: "amp"},
			},
		},
		{
			Name:     "PWA",
			Category: "Mobile",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "service-worker"},
			},
		},
		{
			Name:     "Workbox",
			Category: "PWA",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "workbox"},
			},
		},
		{
			Name:     "Squarespace",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "squarespace"},
			},
		},
		{
			Name:     "Wix",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wix.com"},
			},
		},
		{
			Name:     "Webnode",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webnode"},
			},
		},
		{
			Name:     "Jimdo",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jimdo"},
			},
		},
		{
			Name:     "Tilda",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tilda"},
			},
		},
		{
			Name:     "Weblium",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weblium"},
			},
		},
		{
			Name:     "Readymag",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "readymag"},
			},
		},
		{
			Name:     "Carrd",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "carrd"},
			},
		},
		{
			Name:     "Framer",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "framer"},
			},
		},
		{
			Name:     "WebAssembly",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wasm"},
			},
		},
		{
			Name:     "WebGL",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webgl"},
			},
		},
		{
			Name:     "LaTeX",
			Category: "Document Format",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mathjax"},
			},
		},
		{
			Name:     "MathJax",
			Category: "Math Rendering",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mathjax"},
			},
			VersionRE: `MathJax[/\s]?([\d.]+)`,
		},
		{
			Name:     "KaTeX",
			Category: "Math Rendering",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "katex"},
			},
			VersionRE: `KaTeX[/\s]?([\d.]+)`,
		},
		{
			Name:     "Highlight.js",
			Category: "Syntax Highlighting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "highlight"},
			},
			VersionRE: `Highlight\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Prism",
			Category: "Syntax Highlighting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prism"},
			},
			VersionRE: `Prism[/\s]?([\d.]+)`,
		},
		{
			Name:     "CodeMirror",
			Category: "Code Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "codemirror"},
			},
			VersionRE: `CodeMirror[/\s]?([\d.]+)`,
		},
		{
			Name:     "Monaco Editor",
			Category: "Code Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "monaco"},
			},
		},
		{
			Name:     "Ace",
			Category: "Code Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ace"},
				{Type: "html", Value: "ace-editor"},
			},
			VersionRE: `Ace[/\s]?([\d.]+)`,
		},
		{
			Name:     "TinyMCE",
			Category: "Rich Text Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tinymce"},
			},
			VersionRE: `TinyMCE[/\s]?([\d.]+)`,
		},
		{
			Name:     "CKEditor",
			Category: "Rich Text Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ckeditor"},
				{Type: "html", Value: "cke"},
			},
			VersionRE: `CKEditor[/\s]?([\d.]+)`,
		},
		{
			Name:     "Quill",
			Category: "Rich Text Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "quill"},
			},
			VersionRE: `Quill[/\s]?([\d.]+)`,
		},
		{
			Name:     "Summernote",
			Category: "Rich Text Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "summernote"},
			},
		},
		{
			Name:     "Trumbowyg",
			Category: "Rich Text Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trumbowyg"},
			},
		},
		{
			Name:     "Froala",
			Category: "Rich Text Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "froala"},
			},
		},
		{
			Name:     "Mailchimp",
			Category: "Email Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mailchimp"},
			},
		},
		{
			Name:     "SendGrid",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sendgrid", Field: "X-SG-EID"},
			},
		},
		{
			Name:     "Mailgun",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mailgun", Field: "X-Mailgun-Incoming"},
			},
		},
		{
			Name:     "Postmark",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "postmark", Field: "X-PM-UUID"},
			},
		},
		{
			Name:     "Mandrill",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mandrill", Field: "X-Mandrill-User"},
			},
		},
		{
			Name:     "Amazon SES",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "amazonses", Field: "X-SES-Outgoing"},
			},
		},
		{
			Name:     "Chatra",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chatra"},
			},
		},
		{
			Name:     "Intercom",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "intercom"},
			},
		},
		{
			Name:     "Drift",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drift"},
			},
		},
		{
			Name:     "Zendesk Chat",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zendesk"},
			},
		},
		{
			Name:     "Freshchat",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "freshchat"},
			},
		},
		{
			Name:     "Tawk.to",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tawk"},
			},
		},
		{
			Name:     "Olark",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "olark"},
			},
		},
		{
			Name:     "LiveChat",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "livechat"},
			},
		},
		{
			Name:     "Smartsupp",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "smartsupp"},
			},
		},
		{
			Name:     "Collect.chat",
			Category: "Live Chat",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "collect.chat"},
			},
		},
		{
			Name:     "UserVoice",
			Category: "Customer Feedback",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uservoice"},
			},
		},
		{
			Name:     "Typeform",
			Category: "Form Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "typeform"},
			},
		},
		{
			Name:     "Formstack",
			Category: "Form Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "formstack"},
			},
		},
		{
			Name:     "JotForm",
			Category: "Form Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jotform"},
			},
		},
		{
			Name:     "Wufoo",
			Category: "Form Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wufoo"},
			},
		},
		{
			Name:     "Paperform",
			Category: "Form Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paperform"},
			},
		},
		{
			Name:     "Calendly",
			Category: "Scheduling",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "calendly"},
			},
		},
		{
			Name:     "YouTube",
			Category: "Video",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "youtube"},
				{Type: "html", Value: "yt-player"},
			},
		},
		{
			Name:     "Vimeo",
			Category: "Video",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vimeo"},
				{Type: "html", Value: "player.vimeo.com"},
			},
		},
		{
			Name:     "Bilibili",
			Category: "Video",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bilibili"},
			},
		},
		{
			Name:     "Dailymotion",
			Category: "Video",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dailymotion"},
			},
		},
		{
			Name:     "Twitch",
			Category: "Video",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "twitch"},
			},
		},
		{
			Name:     "Spotify Embed",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spotify"},
			},
		},
		{
			Name:     "SoundCloud",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "soundcloud"},
			},
		},
		{
			Name:     "Bandcamp",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bandcamp"},
			},
		},
		{
			Name:     "AddThis",
			Category: "Social Sharing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "addthis"},
			},
		},
		{
			Name:     "ShareThis",
			Category: "Social Sharing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sharethis"},
			},
		},
		{
			Name:     "AddToAny",
			Category: "Social Sharing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "addtoany"},
			},
		},
		{
			Name:     "Shareaholic",
			Category: "Social Sharing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shareaholic"},
			},
		},
		{
			Name:     "Facebook SDK",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "connect.facebook.net"},
			},
		},
		{
			Name:     "Twitter Widget",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "platform.twitter.com"},
			},
		},
		{
			Name:     "LinkedIn Insight",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin"},
			},
		},
		{
			Name:     "Pinterest",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinterest"},
			},
		},
		{
			Name:     "Disqus",
			Category: "Comment System",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "disqus"},
			},
		},
		{
			Name:     "LiveRe",
			Category: "Comment System",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "livere"},
			},
		},
		{
			Name:     "Duoshuo",
			Category: "Comment System",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "duoshuo"},
			},
		},
		{
			Name:     "uyan",
			Category: "Comment System",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uyan.cc"},
			},
		},
		{
			Name:     "Changyan",
			Category: "Comment System",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "changyan"},
			},
		},
		{
			Name:     "GitLab",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gitlab"},
			},
		},
		{
			Name:     "GitHub",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "github"},
			},
		},
		{
			Name:     "Bitbucket",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bitbucket"},
			},
		},
		{
			Name:     "Gitea",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gitea"},
			},
		},
		{
			Name:     "Gogs",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gogs"},
			},
		},
		{
			Name:     "Portainer",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "portainer"},
			},
		},
		{
			Name:     "Docker",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "docker", Field: "Server"},
			},
		},
		{
			Name:     "Kubernetes",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "k8s", Field: "Server"},
			},
		},
		{
			Name:     "Terraform",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "terraform"},
			},
		},
		{
			Name:     "Ansible",
			Category: "DevOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ansible"},
			},
		},
		{
			Name:     "Jenkins",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jenkins"},
			},
			VersionRE: `Jenkins[/\s]?([\d.]+)`,
		},
		{
			Name:     "GitLab CI",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gitlab"},
			},
		},
		{
			Name:     "GitHub Actions",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "github-actions"},
			},
		},
		{
			Name:     "Travis CI",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "travis"},
			},
		},
		{
			Name:     "CircleCI",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "circleci"},
			},
		},
		{
			Name:     "Drone",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drone"},
			},
		},
		{
			Name:     "Bamboo",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bamboo"},
			},
		},
		{
			Name:     "TeamCity",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "teamcity"},
			},
		},
		{
			Name:     "Azure DevOps",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "azure-devops"},
			},
		},
		{
			Name:     "Sentry",
			Category: "Error Tracking",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sentry"},
			},
			VersionRE: `Sentry[/\s]?([\d.]+)`,
		},
		{
			Name:     "Bugsnag",
			Category: "Error Tracking",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bugsnag"},
			},
		},
		{
			Name:     "Rollbar",
			Category: "Error Tracking",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rollbar"},
			},
		},
		{
			Name:     "New Relic",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "newrelic"},
			},
		},
		{
			Name:     "Datadog",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "datadog"},
			},
		},
		{
			Name:     "Prometheus",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prometheus"},
			},
		},
		{
			Name:     "Grafana",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "grafana"},
			},
			VersionRE: `Grafana[/\s]?([\d.]+)`,
		},
		{
			Name:     "Kibana",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kibana"},
			},
			VersionRE: `Kibana[/\s]?([\d.]+)`,
		},
		{
			Name:     "Elasticsearch",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "elasticsearch", Field: "Server"},
			},
			VersionRE: `Elasticsearch[/\s]?([\d.]+)`,
		},
		{
			Name:     "Solr",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "solr", Field: "Server"},
			},
			VersionRE: `Solr[/\s]?([\d.]+)`,
		},
		{
			Name:     "MeiliSearch",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "meilisearch"},
			},
		},
		{
			Name:     "Typesense",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "typesense"},
			},
		},
		{
			Name:     "Algolia",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "algoliasearch"},
			},
		},
		{
			Name:     "Search by Algolia",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "algolia"},
			},
		},
		{
			Name:     "OpenSearch",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "opensearch", Field: "Server"},
			},
		},
		{
			Name:     "Whoogle",
			Category: "Search",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "whoogle"},
			},
		},
		{
			Name:     "MariaDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mariadb", Field: "Server"},
			},
			VersionRE: `MariaDB[/\s]?([\d.]+)`,
		},
		{
			Name:     "MySQL",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mysql", Field: "Server"},
			},
			VersionRE: `MySQL[/\s]?([\d.]+)`,
		},
		{
			Name:     "PostgreSQL",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "postgres", Field: "Server"},
			},
			VersionRE: `PostgreSQL[/\s]?([\d.]+)`,
		},
		{
			Name:     "MongoDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mongo", Field: "Server"},
			},
			VersionRE: `MongoDB[/\s]?([\d.]+)`,
		},
		{
			Name:     "Redis",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "redis", Field: "Server"},
			},
			VersionRE: `Redis[/\s]?([\d.]+)`,
		},
		{
			Name:     "SQLite",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sqlite", Field: "Server"},
			},
		},
		{
			Name:     "SQL Server",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sqlserver", Field: "Server"},
			},
			VersionRE: `SQL\s*Server[/\s]?([\d.]+)`,
		},
		{
			Name:     "Oracle",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "oracle", Field: "Server"},
			},
			VersionRE: `Oracle[/\s]?([\d.]+)`,
		},
		{
			Name:     "CouchDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "couchdb", Field: "Server"},
			},
			VersionRE: `CouchDB[/\s]?([\d.]+)`,
		},
		{
			Name:     "CouchBase",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "couchbase", Field: "Server"},
			},
		},
		{
			Name:     "Cassandra",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cassandra", Field: "Server"},
			},
		},
		{
			Name:     "InfluxDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "influxdb", Field: "Server"},
			},
			VersionRE: `InfluxDB[/\s]?([\d.]+)`,
		},
		{
			Name:     "TimescaleDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "timescaledb", Field: "Server"},
			},
		},
		{
			Name:     "CockroachDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cockroachdb", Field: "Server"},
			},
		},
		{
			Name:     "Neo4j",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "neo4j", Field: "Server"},
			},
			VersionRE: `Neo4j[/\s]?([\d.]+)`,
		},
		{
			Name:     "ArangoDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "arango", Field: "Server"},
			},
		},
		{
			Name:     "Dgraph",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "dgraph", Field: "Server"},
			},
		},
		{
			Name:     "RavenDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "ravendb", Field: "Server"},
			},
		},
		{
			Name:     "QuestDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "questdb", Field: "Server"},
			},
		},
		{
			Name:     "ClickHouse",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "clickhouse", Field: "Server"},
			},
			VersionRE: `ClickHouse[/\s]?([\d.]+)`,
		},
		{
			Name:     "DuckDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "duckdb", Field: "Server"},
			},
		},
		{
			Name:     "Supabase",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "supabase", Field: "Server"},
			},
		},
		{
			Name:     "Firebase",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "firebase"},
			},
		},
		{
			Name:     "Parse",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "parse"},
			},
		},
		{
			Name:     "PocketBase",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pocketbase"},
			},
		},
		{
			Name:     "NocoDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nocodb"},
			},
		},
		{
			Name:     "Directus",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "directus"},
			},
		},
		{
			Name:     "Strapi",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "strapi"},
			},
			VersionRE: `Strapi[/\s]?([\d.]+)`,
		},
		{
			Name:     "Sanity",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sanity"},
			},
		},
		{
			Name:     "Contentful",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "contentful"},
			},
		},
		{
			Name:     "Storyblok",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "storyblok"},
			},
		},
		{
			Name:     "Prismic",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prismic"},
			},
		},
		{
			Name:     "ButterCMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "buttercms"},
			},
		},
		{
			Name:     "KeystoneJS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "keystone"},
			},
		},
		{
			Name:     "ApostropheCMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apostrophe"},
			},
		},
		{
			Name:     "Publii",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "publii"},
			},
		},
		{
			Name:     "Cockpit",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cockpit"},
			},
		},
		{
			Name:     "Concrete5",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "concrete5"},
				{Type: "html", Value: "Concrete"},
			},
			VersionRE: `Concrete5[/\s]?([\d.]+)`,
		},
		{
			Name:     "Dynamicweb",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dynamicweb"},
			},
		},
		{
			Name:     "EpiServer",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "episerver"},
				{Type: "html", Value: "epi/epi"},
			},
		},
		{
			Name:     "Progress Sitefinity",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sitefinity"},
			},
		},
		{
			Name:     "Orchard",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "orchard"},
			},
		},
		{
			Name:     "DotNetNuke",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dotnetnuke"},
				{Type: "html", Value: "DNN"},
			},
		},
		{
			Name:     "MojoPortal",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mojoportal"},
			},
		},
		{
			Name:     "nopCommerce",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nopcommerce"},
			},
		},
		{
			Name:     "WooCommerce",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "woocommerce"},
				{Type: "html", Value: "wc-api"},
			},
		},
		{
			Name:     "Shopware",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopware"},
			},
			VersionRE: `Shopware[/\s]?([\d.]+)`,
		},
		{
			Name:     "Sylius",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sylius"},
			},
		},
		{
			Name:     "Medusa",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "medusa"},
			},
		},
		{
			Name:     "Saleor",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "saleor"},
			},
		},
		{
			Name:     "Vendure",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vendure"},
			},
		},
		{
			Name:     "Spree",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spree"},
			},
		},
		{
			Name:     "OroCommerce",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "orocrm"},
			},
		},
		{
			Name:     "Akeneo",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "akeneo"},
			},
		},
		{
			Name:     "Elastic Path",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "elasticpath"},
			},
		},
		{
			Name:     "Snipcart",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "snipcart"},
			},
		},
		{
			Name:     "Gumroad",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gumroad"},
			},
		},
		{
			Name:     "Stripe Elements",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "js.stripe.com/v3"},
			},
		},
		{
			Name:     "Razorpay",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "razorpay"},
			},
		},
		{
			Name:     "Lua",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "lua", Field: "X-Powered-By"},
			},
			VersionRE: `Lua[/\s]?([\d.]+)`,
		},
		{
			Name:     "Elixir",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "elixir", Field: "X-Powered-By"},
			},
			VersionRE: `Elixir[/\s]?([\d.]+)`,
		},
		{
			Name:     "Erlang",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "erlang", Field: "X-Powered-By"},
			},
			VersionRE: `Erlang[/\s]?([\d.]+)`,
		},
		{
			Name:     "Dart",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "dart", Field: "X-Powered-By"},
			},
			VersionRE: `Dart[/\s]?([\d.]+)`,
		},
		{
			Name:     "Julia",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "julia", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Haskell",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "haskell", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Scala",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "scala", Field: "X-Powered-By"},
			},
			VersionRE: `Scala[/\s]?([\d.]+)`,
		},
		{
			Name:     "Clojure",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "clojure", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Groovy",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "groovy", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Kotlin",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "kotlin", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Swift",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "swift", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Deno",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "deno", Field: "X-Powered-By"},
			},
			VersionRE: `Deno[/\s]?([\d.]+)`,
		},
		{
			Name:     "Bun",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "bun", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "HHVM",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hhvm", Field: "Server"},
			},
			VersionRE: `HHVM[/\s]?([\d.]+)`,
		},
		{
			Name:     "Hack",
			Category: "Programming Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hack", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "ColdFusion",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "coldfusion", Field: "X-Powered-By"},
			},
			VersionRE: `ColdFusion[/\s]?([\d.]+)`,
		},
		{
			Name:     "Zope",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "zope", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "TurboGears",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "turbogears", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Pylons",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "pylons", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Web2py",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "web2py", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Bottle",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "bottle", Field: "X-Powered-By"},
			},
			VersionRE: `Bottle[/\s]?([\d.]+)`,
		},
		{
			Name:     "CherryPy",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cherrypy", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Falcon",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "falcon", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "FastAPI",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fastapi", Field: "X-Powered-By"},
			},
			VersionRE: `FastAPI[/\s]?([\d.]+)`,
		},
		{
			Name:     "NestJS",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nest", Field: "X-Powered-By"},
			},
			VersionRE: `NestJS[/\s]?([\d.]+)`,
		},
		{
			Name:     "AdonisJS",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "adonisjs", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Hapi",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hapi", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Sails",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sails", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "LoopBack",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "loopback", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Feathers",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "feathers", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Strapi",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "strapi"},
				{Type: "header", Value: "strapi", Field: "X-Powered-By"},
			},
			VersionRE: `Strapi[/\s]?([\d.]+)`,
		},
		{
			Name:     "KeystoneJS",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "keystone"},
			},
		},
		{
			Name:     "Directus",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "directus"},
			},
		},
		{
			Name:     "Contentful",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "contentful"},
			},
		},
		{
			Name:     "Sanity",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sanity"},
			},
		},
		{
			Name:     "Prismic",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prismic"},
			},
		},
		{
			Name:     "Storyblok",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "storyblok"},
			},
		},
		{
			Name:     "ButterCMS",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "buttercms"},
			},
		},
		{
			Name:     "DatoCMS",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "datocms"},
			},
		},
		{
			Name:     "Strapi",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "strapi"},
			},
		},
		{
			Name:     "Contentstack",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "contentstack"},
			},
		},
		{
			Name:     "Builder.io",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "builder.io"},
			},
		},
		{
			Name:     "Hygraph",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hygraph"},
			},
		},
		{
			Name:     "Shopify Hydrogen",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopify"},
				{Type: "header", Value: "hydrogen", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "MedusaJS",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "medusajs"},
			},
		},
		{
			Name:     "Saleor",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "saleor"},
			},
		},
		{
			Name:     "Vendure",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vendure"},
			},
		},
		{
			Name:     "Gatsby",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gatsby"},
			},
			VersionRE: `Gatsby[/\s]?([\d.]+)`,
		},
		{
			Name:     "Next.js",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "next"},
				{Type: "html", Value: "__NEXT"},
			},
			VersionRE: `Next\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Nuxt",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nuxt"},
				{Type: "html", Value: "__NUXT"},
			},
			VersionRE: `Nuxt[/\s]?([\d.]+)`,
		},
		{
			Name:     "SvelteKit",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sveltekit"},
			},
		},
		{
			Name:     "Remix",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "remix"},
			},
			VersionRE: `Remix[/\s]?([\d.]+)`,
		},
		{
			Name:     "Qwik",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qwik"},
			},
		},
		{
			Name:     "SolidStart",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "solid-start"},
			},
		},
		{
			Name:     "Astro",
			Category: "Frontend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "astro"},
			},
			VersionRE: `Astro[/\s]?([\d.]+)`,
		},
		{
			Name:     "Docusaurus",
			Category: "Documentation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "docusaurus"},
			},
			VersionRE: `Docusaurus[/\s]?([\d.]+)`,
		},
		{
			Name:     "VitePress",
			Category: "Documentation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vitepress"},
			},
		},
		{
			Name:     "Storybook",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "storybook"},
			},
		},
		{
			Name:     "Redux",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "redux"},
			},
			VersionRE: `Redux[/\s]?([\d.]+)`,
		},
		{
			Name:     "MobX",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mobx"},
			},
		},
		{
			Name:     "Zustand",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zustand"},
			},
		},
		{
			Name:     "Jotai",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jotai"},
			},
		},
		{
			Name:     "Recoil",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "recoil"},
			},
		},
		{
			Name:     "NgRx",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ngrx"},
			},
		},
		{
			Name:     "Vuex",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vuex"},
			},
		},
		{
			Name:     "Pinia",
			Category: "State Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinia"},
			},
		},
		{
			Name:     "TanStack Query",
			Category: "Data Fetching",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tanstack"},
			},
			VersionRE: `TanStack\s*Query[/\s]?([\d.]+)`,
		},
		{
			Name:     "React Query",
			Category: "Data Fetching",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "react-query"},
			},
		},
		{
			Name:     "SWR",
			Category: "Data Fetching",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "swr"},
			},
		},
		{
			Name:     "Apollo Client",
			Category: "GraphQL Client",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apollo-client"},
			},
		},
		{
			Name:     "urql",
			Category: "GraphQL Client",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "urql"},
			},
		},
		{
			Name:     "Prisma",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prisma"},
			},
			VersionRE: `Prisma[/\s]?([\d.]+)`,
		},
		{
			Name:     "Drizzle ORM",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drizzle"},
			},
		},
		{
			Name:     "Kysely",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kysely"},
			},
		},
		{
			Name:     "Dapper",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "dapper", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Entity Framework",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "entityframework", Field: "X-Powered-By"},
			},
			VersionRE: `Entity\s*Framework[/\s]?([\d.]+)`,
		},
		{
			Name:     "NHibernate",
			Category: "ORM",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nhibernate", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "ServiceStack",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "servicestack", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Nancy",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nancy", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Cocoon",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cocoon", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Mask",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mask", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Yesod",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "yesod", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Snap",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "snap", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Happstack",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "happstack", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Scotty",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "scotty", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Spock",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spock"},
			},
		},
		{
			Name:     "Mockito",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mockito"},
			},
		},
		{
			Name:     "Jest",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jest"},
			},
			VersionRE: `Jest[/\s]?([\d.]+)`,
		},
		{
			Name:     "Mocha",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mocha"},
			},
		},
		{
			Name:     "Jasmine",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jasmine"},
			},
		},
		{
			Name:     "Cypress",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cypress"},
			},
		},
		{
			Name:     "Playwright",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "playwright"},
			},
		},
		{
			Name:     "Puppeteer",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "puppeteer"},
			},
		},
		{
			Name:     "Selenium",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "selenium"},
			},
		},
		{
			Name:     "Vitest",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vitest"},
			},
		},
		{
			Name:     "Pytest",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pytest"},
			},
		},
		{
			Name:     "Robot Framework",
			Category: "Testing Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "robotframework"},
			},
		},
		{
			Name:     "MinIO",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "minio", Field: "Server"},
			},
		},
		{
			Name:     "Ceph",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "ceph", Field: "Server"},
			},
		},
		{
			Name:     "GlusterFS",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "glusterfs", Field: "Server"},
			},
		},
		{
			Name:     "Hadoop",
			Category: "Big Data",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hadoop", Field: "Server"},
			},
			VersionRE: `Hadoop[/\s]?([\d.]+)`,
		},
		{
			Name:     "Spark",
			Category: "Big Data",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "spark", Field: "Server"},
			},
			VersionRE: `Spark[/\s]?([\d.]+)`,
		},
		{
			Name:     "Kafka",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "kafka", Field: "Server"},
			},
			VersionRE: `Kafka[/\s]?([\d.]+)`,
		},
		{
			Name:     "RabbitMQ",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rabbitmq", Field: "Server"},
			},
		},
		{
			Name:     "ActiveMQ",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "activemq", Field: "Server"},
			},
		},
		{
			Name:     "ZeroMQ",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "zeromq", Field: "Server"},
			},
		},
		{
			Name:     "NSQ",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nsq", Field: "Server"},
			},
		},
		{
			Name:     "Pulsar",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "pulsar", Field: "Server"},
			},
		},
		{
			Name:     "NATS",
			Category: "Message Queue",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nats", Field: "Server"},
			},
		},
		{
			Name:     "Redis",
			Category: "Cache",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "redis", Field: "Server"},
			},
			VersionRE: `Redis[/\s]?([\d.]+)`,
		},
		{
			Name:     "Memcached",
			Category: "Cache",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "memcached", Field: "Server"},
			},
		},
		{
			Name:     "Etcd",
			Category: "Key-Value Store",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "etcd", Field: "Server"},
			},
			VersionRE: `etcd[/\s]?([\d.]+)`,
		},
		{
			Name:     "Consul",
			Category: "Service Discovery",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "consul", Field: "Server"},
			},
		},
		{
			Name:     "ZooKeeper",
			Category: "Coordination",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "zookeeper", Field: "Server"},
			},
		},
		{
			Name:     "Nginx Unit",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nginx-unit", Field: "Server"},
			},
		},
		{
			Name:     "Mongrel",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mongrel", Field: "Server"},
			},
		},
		{
			Name:     "Yaws",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "yaws", Field: "Server"},
			},
		},
		{
			Name:     "Cowboy",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cowboy", Field: "Server"},
			},
		},
		{
			Name:     "Misultin",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "misultin", Field: "Server"},
			},
		},
		{
			Name:     "MochiWeb",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mochiweb", Field: "Server"},
			},
		},
		{
			Name:     "Chicago Boss",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "chicagoboss", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Nitrogen",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nitrogen", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Zotonic",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "zotonic", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Radiant",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "radiant"},
			},
		},
		{
			Name:     "BrowserCMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "browsercms"},
			},
		},
		{
			Name:     "LocomotiveCMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "locomotivecms"},
			},
		},
		{
			Name:     "Padrino",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "padrino", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Hanami",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "hanami", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Cuba",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cuba", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Grape",
			Category: "API Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "grape", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "RAML",
			Category: "API Documentation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "raml"},
			},
		},
		{
			Name:     "API Blueprint",
			Category: "API Documentation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apiblueprint"},
			},
		},
		{
			Name:     "R集线器",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnzz"},
			},
		},
		{
			Name:     "51.la",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "51.la"},
				{Type: "html", Value: "51la"},
			},
		},
		{
			Name:     "GrowingIO",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "growingio"},
			},
		},
		{
			Name:     "神策",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sensorsdata"},
			},
		},
		{
			Name:     "TalkingData",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "talkingdata"},
			},
		},
		{
			Name:     "Umeng",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "umeng"},
			},
		},
		{
			Name:     "App Annie",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "appannie"},
			},
		},
		{
			Name:     "Adjust",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "adjust"},
			},
		},
		{
			Name:     "Branch",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "branch"},
			},
		},
		{
			Name:     "Mosquitto",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mosquitto", Field: "Server"},
			},
			VersionRE: `Mosquitto[/\s]?([\d.]+)`,
		},
		{
			Name:     "EMQX",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "emqx", Field: "Server"},
			},
			VersionRE: `EMQX[/\s]?([\d.]+)`,
		},
		{
			Name:     "VerneMQ",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vernemq", Field: "Server"},
			},
		},
		{
			Name:     "RabbitMQ Management",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rabbitmq"},
			},
		},
		{
			Name:     "Node-RED",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "node-red"},
				{Type: "header", Value: "node-red", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Home Assistant",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "home-assistant"},
				{Type: "header", Value: "homeassistant", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "OpenHAB",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "openhab"},
			},
		},
		{
			Name:     "Domoticz",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "domoticz"},
			},
		},
		{
			Name:     "ioBroker",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "iobroker"},
			},
		},
		{
			Name:     "ThingsBoard",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thingsboard"},
			},
		},
		{
			Name:     "DeviceHive",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "devicehive"},
			},
		},
		{
			Name:     "Kaa IoT",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kaa"},
			},
		},
		{
			Name:     "Thinger.io",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thinger.io"},
			},
		},
		{
			Name:     "Mainflux",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mainflux"},
			},
		},
		{
			Name:     "FIWARE",
			Category: "IoT",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fiware"},
			},
		},
		{
			Name:     "Cisco IOS",
			Category: "Network Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cisco-ios", Field: "Server"},
			},
		},
		{
			Name:     "Juniper Junos",
			Category: "Network Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "junos", Field: "Server"},
			},
		},
		{
			Name:     "Huawei VRP",
			Category: "Network Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vrp", Field: "Server"},
			},
		},
		{
			Name:     "H3C Comware",
			Category: "Network Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "comware", Field: "Server"},
			},
		},
		{
			Name:     "MikroTik RouterOS",
			Category: "Network Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "routeros", Field: "Server"},
			},
			VersionRE: `RouterOS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Ubiquiti AirOS",
			Category: "Network Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "airos", Field: "Server"},
			},
		},
		{
			Name:     "Cisco ASA",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cisco-asa", Field: "Server"},
			},
		},
		{
			Name:     "Palo Alto PAN-OS",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "pan-os", Field: "Server"},
			},
		},
		{
			Name:     "FortiOS",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fortios", Field: "Server"},
			},
		},
		{
			Name:     "SonicWALL",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sonicwall", Field: "Server"},
			},
		},
		{
			Name:     "WatchGuard",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "watchguard", Field: "Server"},
			},
		},
		{
			Name:     "Sophos UTM",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "sophos", Field: "Server"},
			},
		},
		{
			Name:     "Barracuda",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "barracuda", Field: "Server"},
			},
		},
		{
			Name:     "Check Point",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "check point", Field: "Server"},
			},
		},
		{
			Name:     "Juniper SRX",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "juniper-srx", Field: "Server"},
			},
		},
		{
			Name:     "Cisco Firepower",
			Category: "Security Device",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "firepower", Field: "Server"},
			},
		},
		{
			Name:     "VMware ESXi",
			Category: "Virtualization",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vmware", Field: "Server"},
			},
			VersionRE: `VMware[/\s]?([\d.]+)`,
		},
		{
			Name:     "Microsoft Hyper-V",
			Category: "Virtualization",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "microsoft-hyper-v", Field: "Server"},
			},
		},
		{
			Name:     "Proxmox VE",
			Category: "Virtualization",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "proxmox", Field: "Server"},
			},
		},
		{
			Name:     "XenServer",
			Category: "Virtualization",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "xenserver", Field: "Server"},
			},
		},
		{
			Name:     "OpenVZ",
			Category: "Virtualization",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "openvz", Field: "Server"},
			},
		},
		{
			Name:     "LXC",
			Category: "Virtualization",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "lxc", Field: "Server"},
			},
		},
		{
			Name:     "Docker",
			Category: "Container",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "docker", Field: "Server"},
			},
			VersionRE: `Docker[/\s]?([\d.]+)`,
		},
		{
			Name:     "containerd",
			Category: "Container",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "containerd", Field: "Server"},
			},
		},
		{
			Name:     "CRI-O",
			Category: "Container",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cri-o", Field: "Server"},
			},
		},
		{
			Name:     "Rancher",
			Category: "Container Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rancher"},
			},
		},
		{
			Name:     "Portainer",
			Category: "Container Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "portainer"},
			},
		},
		{
			Name:     "Docker Swarm",
			Category: "Container Orchestration",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "docker-swarm", Field: "Server"},
			},
		},
		{
			Name:     "Apache Mesos",
			Category: "Container Orchestration",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "mesos", Field: "Server"},
			},
		},
		{
			Name:     "Nomad",
			Category: "Container Orchestration",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nomad", Field: "Server"},
			},
		},
		{
			Name:     "Helm",
			Category: "Package Manager",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "helm"},
			},
		},
		{
			Name:     "Argo CD",
			Category: "GitOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "argo-cd"},
			},
		},
		{
			Name:     "Flux",
			Category: "GitOps",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "flux"},
			},
		},
		{
			Name:     "Jenkins X",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jenkins-x"},
			},
		},
		{
			Name:     "Spinnaker",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spinnaker"},
			},
		},
		{
			Name:     "Argo Workflows",
			Category: "Workflow",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "argo-workflows"},
			},
		},
		{
			Name:     "Airflow",
			Category: "Workflow",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airflow"},
			},
			VersionRE: `Apache\s*Airflow[/\s]?([\d.]+)`,
		},
		{
			Name:     "Dagster",
			Category: "Workflow",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dagster"},
			},
		},
		{
			Name:     "Prefect",
			Category: "Workflow",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prefect"},
			},
		},
		{
			Name:     "Temporal",
			Category: "Workflow",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "temporal"},
			},
		},
		{
			Name:     "Cadence",
			Category: "Workflow",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cadence"},
			},
		},
		{
			Name:     "DooD",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dood"},
			},
		},
		{
			Name:     "Buildkite",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "buildkite"},
			},
		},
		{
			Name:     "Bitbucket Pipelines",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bitbucket-pipelines"},
			},
		},
		{
			Name:     "AWS CodeBuild",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aws-codebuild"},
			},
		},
		{
			Name:     "AWS CodePipeline",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aws-codepipeline"},
			},
		},
		{
			Name:     "Google Cloud Build",
			Category: "CI/CD",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cloud-build"},
			},
		},
		{
			Name:     "Terraform Cloud",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "terraform-cloud"},
			},
		},
		{
			Name:     "Terragrunt",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "terragrunt"},
			},
		},
		{
			Name:     "Pulumi",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pulumi"},
			},
		},
		{
			Name:     "AWS CDK",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aws-cdk"},
			},
		},
		{
			Name:     "Packer",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "packer"},
			},
		},
		{
			Name:     "Vagrant",
			Category: "Development Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vagrant"},
			},
		},
		{
			Name:     "Docker Compose",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "docker-compose"},
			},
		},
		{
			Name:     "DevKinsta",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "devkinsta"},
			},
		},
		{
			Name:     "Lando",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lando"},
			},
		},
		{
			Name:     "DDEV",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ddev"},
			},
		},
		{
			Name:     "Gitpod",
			Category: "Development Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gitpod"},
			},
		},
		{
			Name:     "GitHub Codespaces",
			Category: "Development Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "github-codespaces"},
			},
		},
		{
			Name:     "VS Code Server",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "code-server"},
			},
		},
		{
			Name:     "Theia",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "theia"},
			},
		},
		{
			Name:     "Eclipse Theia",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "eclipse-theia"},
			},
		},
		{
			Name:     "OpenVSCode Server",
			Category: "Development Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "openvscode-server"},
			},
		},
		{
			Name:     "Coder",
			Category: "Development Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coder"},
			},
		},
		{
			Name:     "N8N",
			Category: "Automation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "n8n"},
			},
			VersionRE: `n8n[/\s]?([\d.]+)`,
		},
		{
			Name:     "Zapier",
			Category: "Automation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zapier"},
			},
		},
		{
			Name:     "Make (formerly Integromat)",
			Category: "Automation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "make"},
			},
		},
		{
			Name:     "Microsoft Power Automate",
			Category: "Automation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "powerautomate"},
			},
		},
		{
			Name:     "Apache NiFi",
			Category: "Data Flow",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nifi", Field: "Server"},
			},
			VersionRE: `Apache\s*NiFi[/\s]?([\d.]+)`,
		},
		{
			Name:     "Logstash",
			Category: "Data Processing",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "logstash", Field: "Server"},
			},
			VersionRE: `Logstash[/\s]?([\d.]+)`,
		},
		{
			Name:     "Fluentd",
			Category: "Data Processing",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fluentd", Field: "Server"},
			},
		},
		{
			Name:     "Fluent Bit",
			Category: "Data Processing",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "fluent-bit", Field: "Server"},
			},
		},
		{
			Name:     "Vector",
			Category: "Data Processing",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vector", Field: "Server"},
			},
		},
		{
			Name:     "cksagent",
			Category: "Data Processing",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cksagent", Field: "Server"},
			},
		},
		{
			Name:     "Jaeger",
			Category: "Tracing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jaeger"},
			},
		},
		{
			Name:     "Zipkin",
			Category: "Tracing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zipkin"},
			},
		},
		{
			Name:     "Tempo",
			Category: "Tracing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tempo"},
			},
		},
		{
			Name:     "SkyWalking",
			Category: "APM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skywalking"},
			},
		},
		{
			Name:     "Pinpoint",
			Category: "APM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinpoint"},
			},
		},
		{
			Name:     "OpenTelemetry",
			Category: "Observability",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "opentelemetry"},
			},
		},
		{
			Name:     "OpenCensus",
			Category: "Observability",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "opencensus"},
			},
		},
		{
			Name:     "Lightstep",
			Category: "Observability",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lightstep"},
			},
		},
		{
			Name:     "Instana",
			Category: "APM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "instana"},
			},
		},
		{
			Name:     "AppDynamics",
			Category: "APM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "appdynamics"},
			},
		},
		{
			Name:     "Dynatrace",
			Category: "APM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dynatrace"},
			},
		},
		{
			Name:     "Wavefront",
			Category: "APM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wavefront"},
			},
		},
		{
			Name:     "Humio",
			Category: "Logging",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "humio"},
			},
		},
		{
			Name:     "Loki",
			Category: "Logging",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "loki"},
			},
		},
		{
			Name:     "Mtail",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mtail"},
			},
		},
		{
			Name:     "Uptime Kuma",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uptime-kuma"},
			},
		},
		{
			Name:     "Statping",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "statping"},
			},
		},
		{
			Name:     "Cachet",
			Category: "Status Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cachet"},
			},
		},
		{
			Name:     "Staytus",
			Category: "Status Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "staytus"},
			},
		},
		{
			Name:     "StatusPage.io",
			Category: "Status Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "statuspage.io"},
			},
		},
		{
			Name:     "Instapage",
			Category: "Landing Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "instapage"},
			},
		},
		{
			Name:     "Unbounce",
			Category: "Landing Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "unbounce"},
			},
		},
		{
			Name:     "Leadpages",
			Category: "Landing Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "leadpages"},
			},
		},
		{
			Name:     "Launchrock",
			Category: "Landing Page",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "launchrock"},
			},
		},
		{
			Name:     "About.me",
			Category: "Personal Website",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "about.me"},
			},
		},
		{
			Name:     "Carrd",
			Category: "Website Builder",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "carrd"},
			},
		},
		{
			Name:     "GrapesJS",
			Category: "Web Editor",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "grapesjs"},
			},
		},
		{
			Name:     "TinaCMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tinacms"},
			},
		},
		{
			Name:     "Decap CMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "decapcms"},
			},
		},
		{
			Name:     "Netlify CMS",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "netlify-cms"},
			},
		},
		{
			Name:     "Forestry",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "forestry"},
			},
		},
		{
			Name:     "Contentful",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "contentful"},
			},
		},
		{
			Name:     "Sanity",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sanity"},
			},
		},
		{
			Name:     "Prismic",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prismic"},
			},
		},
		{
			Name:     "Butter CMS",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "buttercms"},
			},
		},
		{
			Name:     "DatoCMS",
			Category: "Headless CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "datocms"},
			},
		},
		{
			Name:     "Scaphold",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "scaphold"},
			},
		},
		{
			Name:     "Back4App",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "back4app"},
			},
		},
		{
			Name:     "Kinvey",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kinvey"},
			},
		},
		{
			Name:     "AWS Amplify",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aws-amplify"},
			},
		},
		{
			Name:     "Firebase",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "firebase"},
			},
		},
		{
			Name:     "Supabase",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "supabase"},
			},
		},
		{
			Name:     "Appwrite",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "appwrite"},
			},
		},
		{
			Name:     "Nhost",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nhost"},
			},
		},
		{
			Name:     "PocketBase",
			Category: "Backend-as-a-Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pocketbase"},
			},
		},
		{
			Name:     "Encore",
			Category: "Backend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "encore"},
			},
		},
		{
			Name:     "WunderGraph",
			Category: "Backend Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wundergraph"},
			},
		},
		{
			Name:     "tRPC",
			Category: "API Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trpc"},
			},
		},
		{
			Name:     "Blitz.js",
			Category: "Fullstack Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blitz"},
			},
		},
		{
			Name:     "RedwoodJS",
			Category: "Fullstack Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "redwood"},
			},
		},
		{
			Name:     "Refine",
			Category: "React Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "refine"},
			},
		},
		{
			Name:     "React-admin",
			Category: "Admin Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "react-admin"},
			},
		},
		{
			Name:     "AdminJS",
			Category: "Admin Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "adminjs"},
			},
		},
		{
			Name:     "Retool",
			Category: "Internal Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "retool"},
			},
		},
		{
			Name:     "Appsmith",
			Category: "Internal Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "appsmith"},
			},
		},
		{
			Name:     "Tooljet",
			Category: "Internal Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tooljet"},
			},
		},
		{
			Name:     "Budibase",
			Category: "Internal Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "budibase"},
			},
		},
		{
			Name:     "Jet Admin",
			Category: "Internal Tool",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jet-admin"},
			},
		},
		{
			Name:     "Moodle",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "moodle"},
				{Type: "html", Value: "Moodle"},
			},
			VersionRE: `Moodle[/\s]?([\d.]+)`,
		},
		{
			Name:     "Canvas LMS",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "canvas"},
				{Type: "html", Value: "canvas-lms"},
			},
		},
		{
			Name:     "Blackboard",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blackboard"},
				{Type: "html", Value: "Bb"},
			},
		},
		{
			Name:     "D2L Brightspace",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "brightspace"},
				{Type: "html", Value: "d2l"},
			},
		},
		{
			Name:     "Schoology",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "schoology"},
			},
		},
		{
			Name:     "Edmodo",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "edmodo"},
			},
		},
		{
			Name:     "Kahoot",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kahoot"},
			},
		},
		{
			Name:     "Quizlet",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "quizlet"},
			},
		},
		{
			Name:     "Coursera",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coursera"},
			},
		},
		{
			Name:     "Udemy",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "udemy"},
			},
		},
		{
			Name:     "edX",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "edx"},
			},
		},
		{
			Name:     "Pluralsight",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pluralsight"},
			},
		},
		{
			Name:     "Skillshare",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skillshare"},
			},
		},
		{
			Name:     "MasterClass",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "masterclass"},
			},
		},
		{
			Name:     "Teachable",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "teachable"},
			},
		},
		{
			Name:     "Thinkific",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thinkific"},
			},
		},
		{
			Name:     "Kajabi",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kajabi"},
			},
		},
		{
			Name:     "LearnWorlds",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "learnworlds"},
			},
		},
		{
			Name:     "Ruzuku",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ruzuku"},
			},
		},
		{
			Name:     "Academy of Mine",
			Category: "EdTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "academyofmine"},
			},
		},
		{
			Name:     "PayPal",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paypal"},
			},
		},
		{
			Name:     "Stripe",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "js.stripe.com"},
			},
		},
		{
			Name:     "Square",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "squareup"},
			},
		},
		{
			Name:     "Adyen",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "adyen"},
			},
		},
		{
			Name:     "Braintree",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "braintreepayments"},
			},
		},
		{
			Name:     "Worldpay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "worldpay"},
			},
		},
		{
			Name:     "Authorize.net",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "authorizenet"},
			},
		},
		{
			Name:     "2Checkout",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "2checkout"},
			},
		},
		{
			Name:     "Skrill",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skrill"},
			},
		},
		{
			Name:     "Neteller",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "neteller"},
			},
		},
		{
			Name:     "PayU",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "payu"},
			},
		},
		{
			Name:     "Alipay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alipay"},
			},
		},
		{
			Name:     "WeChat Pay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wechat"},
			},
		},
		{
			Name:     "UnionPay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "unionpay"},
			},
		},
		{
			Name:     "Klarna",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "klarna"},
			},
		},
		{
			Name:     "Afterpay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "afterpay"},
			},
		},
		{
			Name:     "Affirm",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "affirm"},
			},
		},
		{
			Name:     "Sezzle",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sezzle"},
			},
		},
		{
			Name:     "Splitit",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "splitit"},
			},
		},
		{
			Name:     "Bread",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bread"},
			},
		},
		{
			Name:     "ChargeAfter",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chargeafter"},
			},
		},
		{
			Name:     "Razorpay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "razorpay"},
			},
		},
		{
			Name:     "Paytm",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paytm"},
			},
		},
		{
			Name:     "PhonePe",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "phonepe"},
			},
		},
		{
			Name:     "Google Pay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "googlepay"},
			},
		},
		{
			Name:     "Apple Pay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "applepay"},
			},
		},
		{
			Name:     "Samsung Pay",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "samsungpay"},
			},
		},
		{
			Name:     "Robinhood",
			Category: "FinTech",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "robinhood"},
			},
		},
		{
			Name:     "Coinbase",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coinbase"},
			},
		},
		{
			Name:     "Binance",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "binance"},
			},
		},
		{
			Name:     "Kraken",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kraken"},
			},
		},
		{
			Name:     "Bitfinex",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bitfinex"},
			},
		},
		{
			Name:     "Bitstamp",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bitstamp"},
			},
		},
		{
			Name:     "OKX",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "okx"},
			},
		},
		{
			Name:     "Huobi",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "huobi"},
			},
		},
		{
			Name:     "MetaMask",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "metamask"},
			},
		},
		{
			Name:     "Trust Wallet",
			Category: "Crypto",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trustwallet"},
			},
		},
		{
			Name:     "Steam",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "steam"},
			},
		},
		{
			Name:     "PlayStation Network",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "playstation"},
			},
		},
		{
			Name:     "Xbox Live",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xbox"},
			},
		},
		{
			Name:     "Nintendo",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nintendo"},
			},
		},
		{
			Name:     "Epic Games",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "epicgames"},
			},
		},
		{
			Name:     "GOG",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gog"},
			},
		},
		{
			Name:     "itch.io",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "itch.io"},
			},
		},
		{
			Name:     "Roblox",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "roblox"},
			},
		},
		{
			Name:     "Minecraft",
			Category: "Gaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "minecraft"},
			},
		},
		{
			Name:     "Twitch",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "twitch"},
			},
		},
		{
			Name:     "YouTube",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "youtube"},
			},
		},
		{
			Name:     "Netflix",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "netflix"},
			},
		},
		{
			Name:     "Disney+",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "disneyplus"},
			},
		},
		{
			Name:     "HBO Max",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hbomax"},
			},
		},
		{
			Name:     "Hulu",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hulu"},
			},
		},
		{
			Name:     "Apple TV+",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "appletv"},
			},
		},
		{
			Name:     "Amazon Prime Video",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "primevideo"},
			},
		},
		{
			Name:     "Paramount+",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paramountplus"},
			},
		},
		{
			Name:     "Peacock",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "peacock"},
			},
		},
		{
			Name:     "Spotify",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spotify"},
			},
		},
		{
			Name:     "Apple Music",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "applemusic"},
			},
		},
		{
			Name:     "SoundCloud",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "soundcloud"},
			},
		},
		{
			Name:     "Pandora",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pandora"},
			},
		},
		{
			Name:     "Deezer",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deezer"},
			},
		},
		{
			Name:     "Tidal",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tidal"},
			},
		},
		{
			Name:     "Amazon Music",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "amazonmusic"},
			},
		},
		{
			Name:     "YouTube Music",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "youtubemusic"},
			},
		},
		{
			Name:     "Discord",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discord"},
			},
		},
		{
			Name:     "Slack",
			Category: "Collaboration",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "slack"},
			},
		},
		{
			Name:     "Microsoft Teams",
			Category: "Collaboration",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "teams"},
			},
		},
		{
			Name:     "Zoom",
			Category: "Video Conferencing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zoom"},
			},
		},
		{
			Name:     "Google Meet",
			Category: "Video Conferencing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "meet"},
			},
		},
		{
			Name:     "Cisco Webex",
			Category: "Video Conferencing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webex"},
			},
		},
		{
			Name:     "GoToMeeting",
			Category: "Video Conferencing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gotomeeting"},
			},
		},
		{
			Name:     "BlueJeans",
			Category: "Video Conferencing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bluejeans"},
			},
		},
		{
			Name:     "Jitsi",
			Category: "Video Conferencing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jitsi"},
			},
		},
		{
			Name:     "Mattermost",
			Category: "Collaboration",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mattermost"},
			},
		},
		{
			Name:     "Rocket.Chat",
			Category: "Collaboration",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rocket.chat"},
			},
		},
		{
			Name:     "Zulip",
			Category: "Collaboration",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zulip"},
			},
		},
		{
			Name:     "Element",
			Category: "Collaboration",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "element"},
			},
		},
		{
			Name:     "Telegram",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "telegram"},
			},
		},
		{
			Name:     "WhatsApp",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "whatsapp"},
			},
		},
		{
			Name:     "Facebook",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "facebook"},
			},
		},
		{
			Name:     "Twitter",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "twitter"},
			},
		},
		{
			Name:     "Instagram",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "instagram"},
			},
		},
		{
			Name:     "LinkedIn",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin"},
			},
		},
		{
			Name:     "Reddit",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "reddit"},
			},
		},
		{
			Name:     "Pinterest",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinterest"},
			},
		},
		{
			Name:     "TikTok",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tiktok"},
			},
		},
		{
			Name:     "Snapchat",
			Category: "Social",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "snapchat"},
			},
		},
		{
			Name:     "Vimeo",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vimeo"},
			},
		},
		{
			Name:     "Dailymotion",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dailymotion"},
			},
		},
		{
			Name:     "Bilibili",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bilibili"},
			},
		},
		{
			Name:     "Acfun",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "acfun"},
			},
		},
		{
			Name:     "Douyin",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "douyin"},
			},
		},
		{
			Name:     "Kuaishou",
			Category: "Streaming",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kuaishou"},
			},
		},
		{
			Name:     "Mixcloud",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mixcloud"},
			},
		},
		{
			Name:     "Bandcamp",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bandcamp"},
			},
		},
		{
			Name:     "Last.fm",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "last.fm"},
			},
		},
		{
			Name:     "Genius",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "genius"},
			},
		},
		{
			Name:     "AZMusic",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "azlyrics"},
			},
		},
		{
			Name:     "SongMeanings",
			Category: "Music",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "songmeanings"},
			},
		},
		{
			Name:     "Genius",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "genius"},
			},
		},
		{
			Name:     "Musixmatch",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "musixmatch"},
			},
		},
		{
			Name:     "AZLyrics",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "azlyrics"},
			},
		},
		{
			Name:     "MetroLyrics",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "metrolyrics"},
			},
		},
		{
			Name:     "SongLyrics",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "songlyrics"},
			},
		},
		{
			Name:     "LyricWiki",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lyricwiki"},
			},
		},
		{
			Name:     "LyricsMode",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lyricsMode"},
			},
		},
		{
			Name:     "CleanFly",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cleanfly"},
			},
		},
		{
			Name:     "Paroles_net",
			Category: "Lyrics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paroles.net"},
			},
		},
		{
			Name:     "Gouvernement_fr",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "gouv", Field: "Server"},
			},
		},
		{
			Name:     "USA.gov",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "usa.gov"},
			},
		},
		{
			Name:     "Gov.uk",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.uk"},
			},
		},
		{
			Name:     "Australia.gov.au",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.au"},
			},
		},
		{
			Name:     "Canada.ca",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "canada.ca"},
			},
		},
		{
			Name:     "Japan.go.jp",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "go.jp"},
			},
		},
		{
			Name:     "Singapore.gov.sg",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.sg"},
			},
		},
		{
			Name:     "Gov.hk",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.hk"},
			},
		},
		{
			Name:     "Taiwan.gov.tw",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.tw"},
			},
		},
		{
			Name:     "欧盟",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "europa.eu"},
			},
		},
		{
			Name:     "联合国",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "un.org"},
			},
		},
		{
			Name:     "WHO",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "who.int"},
			},
		},
		{
			Name:     "World Bank",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "worldbank.org"},
			},
		},
		{
			Name:     "IMF",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "imf.org"},
			},
		},
		{
			Name:     "BBC",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bbc.com"},
			},
		},
		{
			Name:     "CNN",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnn.com"},
			},
		},
		{
			Name:     "Fox News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "foxnews.com"},
			},
		},
		{
			Name:     "MSNBC",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "msnbc.com"},
			},
		},
		{
			Name:     "CBS News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cbsnews.com"},
			},
		},
		{
			Name:     "ABC News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "abcnews.go.com"},
			},
		},
		{
			Name:     "NBC News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nbcnews.com"},
			},
		},
		{
			Name:     "The New York Times",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nytimes.com"},
			},
		},
		{
			Name:     "The Washington Post",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "washingtonpost.com"},
			},
		},
		{
			Name:     "The Guardian",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "theguardian.com"},
			},
		},
		{
			Name:     "The Wall Street Journal",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wsj.com"},
			},
		},
		{
			Name:     "Reuters",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "reuters.com"},
			},
		},
		{
			Name:     "Associated Press",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apnews.com"},
			},
		},
		{
			Name:     "Bloomberg",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bloomberg.com"},
			},
		},
		{
			Name:     "Financial Times",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ft.com"},
			},
		},
		{
			Name:     "Forbes",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "forbes.com"},
			},
		},
		{
			Name:     "Business Insider",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "businessinsider.com"},
			},
		},
		{
			Name:     "HuffPost",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "huffpost.com"},
			},
		},
		{
			Name:     "BuzzFeed",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "buzzfeed.com"},
			},
		},
		{
			Name:     "Vox",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vox.com"},
			},
		},
		{
			Name:     "Axios",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "axios.com"},
			},
		},
		{
			Name:     "Politico",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "politico.com"},
			},
		},
		{
			Name:     "The Hill",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thehill.com"},
			},
		},
		{
			Name:     "Breitbart",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "breitbart.com"},
			},
		},
		{
			Name:     "Daily Mail",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dailymail.co.uk"},
			},
		},
		{
			Name:     "The Telegraph",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "telegraph.co.uk"},
			},
		},
		{
			Name:     "Daily Express",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "express.co.uk"},
			},
		},
		{
			Name:     "Daily Mirror",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mirror.co.uk"},
			},
		},
		{
			Name:     "Sky News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sky.com"},
			},
		},
		{
			Name:     "Al Jazeera",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aljazeera.com"},
			},
		},
		{
			Name:     "France 24",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "france24.com"},
			},
		},
		{
			Name:     "Euronews",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "euronews.com"},
			},
		},
		{
			Name:     "RT",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rt.com"},
			},
		},
		{
			Name:     "TASS",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tass.com"},
			},
		},
		{
			Name:     "Xinhua",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xinhuanet.com"},
			},
		},
		{
			Name:     "China Daily",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chinadaily.com.cn"},
			},
		},
		{
			Name:     "NHK",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nhk.or.jp"},
			},
		},
		{
			Name:     "KBS",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kbs.co.kr"},
			},
		},
		{
			Name:     "SBS",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sbs.co.kr"},
			},
		},
		{
			Name:     "联合早报",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zaobao.com"},
			},
		},
		{
			Name:     "澎湃新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thepaper.cn"},
			},
		},
		{
			Name:     "今日头条",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "toutiao.com"},
			},
		},
		{
			Name:     "搜狐新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sohu.com"},
			},
		},
		{
			Name:     "网易新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "163.com"},
			},
		},
		{
			Name:     "新浪新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sina.com.cn"},
			},
		},
		{
			Name:     "凤凰网",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ifeng.com"},
			},
		},
		{
			Name:     "Medium",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "medium.com"},
			},
		},
		{
			Name:     "WordPress.com",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wordpress.com"},
			},
		},
		{
			Name:     "Blogger",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blogger.com"},
			},
		},
		{
			Name:     "Tumblr",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tumblr.com"},
			},
		},
		{
			Name:     "Wix",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wix.com"},
			},
		},
		{
			Name:     "Squarespace",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "squarespace.com"},
			},
		},
		{
			Name:     "Weebly",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weebly.com"},
			},
		},
		{
			Name:     "Ghost",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ghost.org"},
			},
		},
		{
			Name:     "Substack",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "substack.com"},
			},
		},
		{
			Name:     "Patreon",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "patreon.com"},
			},
		},
		{
			Name:     "Kickstarter",
			Category: "Crowdfunding",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kickstarter.com"},
			},
		},
		{
			Name:     "Indiegogo",
			Category: "Crowdfunding",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "indiegogo.com"},
			},
		},
		{
			Name:     "GoFundMe",
			Category: "Crowdfunding",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gofundme.com"},
			},
		},
		{
			Name:     "JustGiving",
			Category: "Crowdfunding",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "justgiving.com"},
			},
		},
		{
			Name:     "Zoe",
			Category: "Crowdfunding",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zoopla.co.uk"},
			},
		},
		{
			Name:     "Rightmove",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rightmove.co.uk"},
			},
		},
		{
			Name:     "Rightmove",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rightmove"},
			},
		},
		{
			Name:     "Zoopla",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zoopla"},
			},
		},
		{
			Name:     "OnTheMarket",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "onthemarket.com"},
			},
		},
		{
			Name:     " apartments.com",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apartments.com"},
			},
		},
		{
			Name:     "Zillow",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zillow.com"},
			},
		},
		{
			Name:     "Redfin",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "redfin.com"},
			},
		},
		{
			Name:     "Trulia",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trulia.com"},
			},
		},
		{
			Name:     "Realtor.com",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "realtor.com"},
			},
		},
		{
			Name:     "Compass",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "compass.com"},
			},
		},
		{
			Name:     "Sotheby's",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sothebysrealty.com"},
			},
		},
		{
			Name:     "Coldwell Banker",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coldwellbanker.com"},
			},
		},
		{
			Name:     "Century 21",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "century21.com"},
			},
		},
		{
			Name:     "贝壳找房",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ke.com"},
			},
		},
		{
			Name:     "链家",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lianjia.com"},
			},
		},
		{
			Name:     "自如",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ziroom.com"},
			},
		},
		{
			Name:     "蛋壳公寓",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dankegongyu.com"},
			},
		},
		{
			Name:     "Airbnb",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airbnb.com"},
			},
		},
		{
			Name:     "Booking.com",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "booking.com"},
			},
		},
		{
			Name:     "Expedia",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "expedia.com"},
			},
		},
		{
			Name:     "TripAdvisor",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tripadvisor.com"},
			},
		},
		{
			Name:     "Hotels.com",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hotels.com"},
			},
		},
		{
			Name:     "Agoda",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "agoda.com"},
			},
		},
		{
			Name:     "Kayak",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kayak.com"},
			},
		},
		{
			Name:     "Skyscanner",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skyscanner.com"},
			},
		},
		{
			Name:     "Google Flights",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "google.com/flights"},
			},
		},
		{
			Name:     "United Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "united.com"},
			},
		},
		{
			Name:     "Delta",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "delta.com"},
			},
		},
		{
			Name:     "American Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aa.com"},
			},
		},
		{
			Name:     "Southwest Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "southwest.com"},
			},
		},
		{
			Name:     "JetBlue",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jetblue.com"},
			},
		},
		{
			Name:     "Alaska Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alaskaair.com"},
			},
		},
		{
			Name:     "Hawaiian Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hawaiianairlines.com"},
			},
		},
		{
			Name:     "Spirit Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spirit.com"},
			},
		},
		{
			Name:     "Emirates",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "emirates.com"},
			},
		},
		{
			Name:     "Qatar Airways",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qatarairways.com"},
			},
		},
		{
			Name:     "Singapore Airlines",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "singaporeair.com"},
			},
		},
		{
			Name:     "Cathay Pacific",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cathaypacific.com"},
			},
		},
		{
			Name:     " Lufthansa",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lufthansa.com"},
			},
		},
		{
			Name:     "Air France",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airfrance.com"},
			},
		},
		{
			Name:     "KLM",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "klm.com"},
			},
		},
		{
			Name:     "British Airways",
			Category: "Travel",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "britishairways.com"},
			},
		},
		{
			Name:     "Uber",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uber.com"},
			},
		},
		{
			Name:     "Lyft",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lyft.com"},
			},
		},
		{
			Name:     "Grab",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "grab.com"},
			},
		},
		{
			Name:     "DiDi",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "didiglobal.com"},
			},
		},
		{
			Name:     "Ola",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "olacabs.com"},
			},
		},
		{
			Name:     "Careem",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "careem.com"},
			},
		},
		{
			Name:     "Bolt",
			Category: "Transportation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bolt.eu"},
			},
		},
		{
			Name:     "DoorDash",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "doordash.com"},
			},
		},
		{
			Name:     "Uber Eats",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ubereats.com"},
			},
		},
		{
			Name:     "Grubhub",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "grubhub.com"},
			},
		},
		{
			Name:     "Just Eat",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "justeat.com"},
			},
		},
		{
			Name:     "Deliveroo",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deliveroo.com"},
			},
		},
		{
			Name:     "Postmates",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "postmates.com"},
			},
		},
		{
			Name:     " Seamless",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "seamless.com"},
			},
		},
		{
			Name:     "Caviar",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trycaviar.com"},
			},
		},
		{
			Name:     "Takeaway.com",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "takeaway.com"},
			},
		},
		{
			Name:     "Menulog",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "menulog.com.au"},
			},
		},
		{
			Name:     "Foodpanda",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "foodpanda.com"},
			},
		},
		{
			Name:     "饿了么",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ele.me"},
			},
		},
		{
			Name:     "美团外卖",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "meituan.com"},
			},
		},
		{
			Name:     "百度外卖",
			Category: "Food Delivery",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "waimai.baidu.com"},
			},
		},
		{
			Name:     "Daphne",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "daphne"},
			},
		},
		{
			Name:     "Zocdoc",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zocdoc.com"},
			},
		},
		{
			Name:     "Healthgrades",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "healthgrades.com"},
			},
		},
		{
			Name:     "Vitals",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vitals.com"},
			},
		},
		{
			Name:     "WebMD",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webmd.com"},
			},
		},
		{
			Name:     "Mayo Clinic",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mayoclinic.org"},
			},
		},
		{
			Name:     "Cleveland Clinic",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "clevelandclinic.org"},
			},
		},
		{
			Name:     "Johns Hopkins Medicine",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hopkinsmedicine.org"},
			},
		},
		{
			Name:     "NIH",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nih.gov"},
			},
		},
		{
			Name:     "CDC",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cdc.gov"},
			},
		},
		{
			Name:     "WHO",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "who.int"},
			},
		},
		{
			Name:     "好大夫在线",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "haodf.com"},
			},
		},
		{
			Name:     "丁香园",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dxy.cn"},
			},
		},
		{
			Name:     "微医",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "guahao.com"},
			},
		},
		{
			Name:     "平安健康",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pingan.com"},
			},
		},
		{
			Name:     "丁香医生",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dxys.com"},
			},
		},
		{
			Name:     "阿里健康",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alijk.com"},
			},
		},
		{
			Name:     "京东健康",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jd.com"},
			},
		},
		{
			Name:     "1号药店",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "111.com.cn"},
			},
		},
		{
			Name:     "叮当快药",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ddky.com"},
			},
		},
		{
			Name:     "Amazon Pharmacy",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pharmacy.amazon.com"},
			},
		},
		{
			Name:     "CVS Pharmacy",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cvs.com"},
			},
		},
		{
			Name:     "Walgreens",
			Category: "Healthcare",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "walgreens.com"},
			},
		},
		{
			Name:     "US Government",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "usa.gov"},
				{Type: "header", Value: "X-USA-ID: .*"},
			},
		},
		{
			Name:     "UK Government",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.uk"},
				{Type: "header", Value: "X-Gov-ID: .*"},
			},
		},
		{
			Name:     "Australian Government",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gov.au"},
			},
		},
		{
			Name:     "Canadian Government",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "canada.ca"},
			},
		},
		{
			Name:     "European Union",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "europa.eu"},
			},
		},
		{
			Name:     "United Nations",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "un.org"},
			},
		},
		{
			Name:     "World Bank",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "worldbank.org"},
			},
		},
		{
			Name:     "IRS",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "irs.gov"},
			},
		},
		{
			Name:     "NASA",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nasa.gov"},
			},
		},
		{
			Name:     "FBI",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fbi.gov"},
			},
		},
		{
			Name:     "CIA",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cia.gov"},
			},
		},
		{
			Name:     "NIH",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nih.gov"},
			},
		},
		{
			Name:     "CDC",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cdc.gov"},
			},
		},
		{
			Name:     "WHO",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "who.int"},
			},
		},
		{
			Name:     "USPS",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "usps.com"},
			},
		},
		{
			Name:     "中国社会保险",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "si.gov.cn"},
			},
		},
		{
			Name:     "国家政务服务",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gjzwfw.gov.cn"},
			},
		},
		{
			Name:     "北京市政务服务",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "beijing.gov.cn"},
			},
		},
		{
			Name:     "上海市政府",
			Category: "Government",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shanghai.gov.cn"},
			},
		},
		{
			Name:     "MIT",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mit.edu"},
				{Type: "header", Value: "X-Drupal-Cache: .*"},
			},
		},
		{
			Name:     "Stanford University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stanford.edu"},
			},
		},
		{
			Name:     "Harvard University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "harvard.edu"},
			},
		},
		{
			Name:     "Yale University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yale.edu"},
			},
		},
		{
			Name:     "Princeton University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "princeton.edu"},
			},
		},
		{
			Name:     "UC Berkeley",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "berkeley.edu"},
			},
		},
		{
			Name:     "Oxford University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ox.ac.uk"},
			},
		},
		{
			Name:     "Cambridge University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cam.ac.uk"},
			},
		},
		{
			Name:     "Cornell University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cornell.edu"},
			},
		},
		{
			Name:     "Columbia University",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "columbia.edu"},
			},
		},
		{
			Name:     "UCLA",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ucla.edu"},
			},
		},
		{
			Name:     "University of Michigan",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "umich.edu"},
			},
		},
		{
			Name:     "Coursera",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coursera.org"},
				{Type: "header", Value: "X-Coursera-Request-Id: .*"},
			},
		},
		{
			Name:     "edX",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "edx.org"},
			},
		},
		{
			Name:     "Khan Academy",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "khanacademy.org"},
			},
		},
		{
			Name:     "Udemy",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "udemy.com"},
			},
		},
		{
			Name:     "Duolingo",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "duolingo.com"},
			},
		},
		{
			Name:     "Skillshare",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skillshare.com"},
			},
		},
		{
			Name:     "Pluralsight",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pluralsight.com"},
			},
		},
		{
			Name:     "LinkedIn Learning",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin.com/learning"},
			},
		},
		{
			Name:     "MasterClass",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "masterclass.com"},
			},
		},
		{
			Name:     "中国大学MOOC",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "icourse163.org"},
			},
		},
		{
			Name:     "学堂在线",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xuetangx.com"},
			},
		},
		{
			Name:     "猿辅导",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yuanfudao.com"},
			},
		},
		{
			Name:     "作业帮",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zuoyebang.com"},
			},
		},
		{
			Name:     "学而思网校",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xueersi.com"},
			},
		},
		{
			Name:     "新东方在线",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "koolearn.com"},
			},
		},
		{
			Name:     "Quizlet",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "quizlet.com"},
			},
		},
		{
			Name:     "Chegg",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chegg.com"},
			},
		},
		{
			Name:     "Course Hero",
			Category: "Education",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coursehero.com"},
			},
		},
		{
			Name:     "JPMorgan Chase",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chase.com"},
			},
		},
		{
			Name:     "Bank of America",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bankofamerica.com"},
			},
		},
		{
			Name:     "Wells Fargo",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wellsfargo.com"},
			},
		},
		{
			Name:     "Citibank",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "citibank.com"},
			},
		},
		{
			Name:     "Goldman Sachs",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "goldmansachs.com"},
			},
		},
		{
			Name:     "Morgan Stanley",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "morganstanley.com"},
			},
		},
		{
			Name:     "HSBC",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hsbc.com"},
			},
		},
		{
			Name:     "Barclays",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "barclays.com"},
			},
		},
		{
			Name:     "Deutsche Bank",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deutsche-bank.com"},
			},
		},
		{
			Name:     "UBS",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ubs.com"},
			},
		},
		{
			Name:     "Charles Schwab",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "schwab.com"},
			},
		},
		{
			Name:     "TD Ameritrade",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tdameritrade.com"},
			},
		},
		{
			Name:     "Robinhood",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "robinhood.com"},
			},
		},
		{
			Name:     "E*TRADE",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "etrade.com"},
			},
		},
		{
			Name:     "Fidelity",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fidelity.com"},
			},
		},
		{
			Name:     "Vanguard",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vanguard.com"},
			},
		},
		{
			Name:     "BlackRock",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blackrock.com"},
			},
		},
		{
			Name:     "State Street",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "statestreet.com"},
			},
		},
		{
			Name:     "PayPal",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paypal.com"},
			},
		},
		{
			Name:     "Venmo",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "venmo.com"},
			},
		},
		{
			Name:     "Cash App",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cash.app"},
			},
		},
		{
			Name:     "Zelle",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zellepay.com"},
			},
		},
		{
			Name:     "TransferWise",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wise.com"},
			},
		},
		{
			Name:     "Revolut",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "revolut.com"},
			},
		},
		{
			Name:     "NerdWallet",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nerdwallet.com"},
			},
		},
		{
			Name:     "Coinbase",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coinbase.com"},
			},
		},
		{
			Name:     "Binance",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "binance.com"},
			},
		},
		{
			Name:     "Kraken",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kraken.com"},
			},
		},
		{
			Name:     "BlockFi",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blockfi.com"},
			},
		},
		{
			Name:     "Robinhood Crypto",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "robinhood.com"},
			},
		},
		{
			Name:     "支付宝",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alipay.com"},
			},
		},
		{
			Name:     "微信支付",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weixin.qq.com"},
			},
		},
		{
			Name:     "招商银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cmbchina.com"},
			},
		},
		{
			Name:     "工商银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "icbc.com.cn"},
			},
		},
		{
			Name:     "建设银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ccb.com"},
			},
		},
		{
			Name:     "农业银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "abchina.com"},
			},
		},
		{
			Name:     "中国银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "boc.cn"},
			},
		},
		{
			Name:     "交通银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bankcomm.com"},
			},
		},
		{
			Name:     "邮储银行",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "psbc.com"},
			},
		},
		{
			Name:     "蚂蚁金服",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "antgroup.com"},
			},
		},
		{
			Name:     "陆金所",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lu.com"},
			},
		},
		{
			Name:     "京东金融",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jr.jd.com"},
			},
		},
		{
			Name:     "陆金所",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lu.com"},
			},
		},
		{
			Name:     "人人贷",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "renrendai.com"},
			},
		},
		{
			Name:     "宜信",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "creditcore.cn"},
			},
		},
		{
			Name:     "P2P Financial",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ppdai.com"},
			},
		},
		{
			Name:     "Stocktwits",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stocktwits.com"},
			},
		},
		{
			Name:     "Seeking Alpha",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "seekingalpha.com"},
			},
		},
		{
			Name:     "Morningstar",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "morningstar.com"},
			},
		},
		{
			Name:     "Bloomberg",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bloomberg.com"},
			},
		},
		{
			Name:     "Reuters",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "reuters.com"},
			},
		},
		{
			Name:     "Financial Times",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ft.com"},
			},
		},
		{
			Name:     "Wall Street Journal",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wsj.com"},
			},
		},
		{
			Name:     "Investopedia",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "investopedia.com"},
			},
		},
		{
			Name:     "MarketWatch",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "marketwatch.com"},
			},
		},
		{
			Name:     "Yahoo Finance",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "finance.yahoo.com"},
			},
		},
		{
			Name:     "Google Finance",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "google.com/finance"},
			},
		},
		{
			Name:     "CNBC",
			Category: "Finance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnbc.com"},
			},
		},
		{
			Name:     "NFL",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nfl.com"},
			},
		},
		{
			Name:     "NBA",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nba.com"},
			},
		},
		{
			Name:     "MLB",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mlb.com"},
			},
		},
		{
			Name:     "NHL",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nhl.com"},
			},
		},
		{
			Name:     "FIFA",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fifa.com"},
			},
		},
		{
			Name:     "UEFA",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uefa.com"},
			},
		},
		{
			Name:     "ESPN",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "espn.com"},
			},
		},
		{
			Name:     "CBS Sports",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cbssports.com"},
			},
		},
		{
			Name:     "Fox Sports",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "foxsports.com"},
			},
		},
		{
			Name:     "Bleacher Report",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bleacherreport.com"},
			},
		},
		{
			Name:     "Sky Sports",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skysports.com"},
			},
		},
		{
			Name:     "The Athletic",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "theathletic.com"},
			},
		},
		{
			Name:     "Goal.com",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "goal.com"},
			},
		},
		{
			Name:     "Sportradar",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sportradar.com"},
			},
		},
		{
			Name:     "Formula 1",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "formula1.com"},
			},
		},
		{
			Name:     "WWE",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wwe.com"},
			},
		},
		{
			Name:     "UFC",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ufc.com"},
			},
		},
		{
			Name:     "ATP Tour",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "atptour.com"},
			},
		},
		{
			Name:     "WTA Tour",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wtatennis.com"},
			},
		},
		{
			Name:     "NCAA",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ncaa.com"},
			},
		},
		{
			Name:     "Olympic",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "olympic.org"},
			},
		},
		{
			Name:     "新浪体育",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sports.sina.com.cn"},
			},
		},
		{
			Name:     "虎扑",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hupu.com"},
			},
		},
		{
			Name:     "腾讯体育",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sports.qq.com"},
			},
		},
		{
			Name:     "懂球帝",
			Category: "Sports",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dongqiudi.com"},
			},
		},
		{
			Name:     "Netflix",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "netflix.com"},
				{Type: "header", Value: "X-Netflix\\.nl: .*"},
			},
		},
		{
			Name:     "Disney+",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "disneyplus.com"},
			},
		},
		{
			Name:     "HBO Max",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hbomax.com"},
			},
		},
		{
			Name:     "Amazon Prime Video",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "primevideo.com"},
			},
		},
		{
			Name:     "Apple TV+",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tv.apple.com"},
			},
		},
		{
			Name:     "Hulu",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hulu.com"},
			},
		},
		{
			Name:     "Peacock",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "peacocktv.com"},
			},
		},
		{
			Name:     "Paramount+",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paramountplus.com"},
			},
		},
		{
			Name:     "YouTube",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "youtube.com"},
			},
		},
		{
			Name:     "Twitch",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "twitch.tv"},
			},
		},
		{
			Name:     "Spotify",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spotify.com"},
			},
		},
		{
			Name:     "Apple Music",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "music.apple.com"},
			},
		},
		{
			Name:     "Amazon Music",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "music.amazon.com"},
			},
		},
		{
			Name:     "SoundCloud",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "soundcloud.com"},
			},
		},
		{
			Name:     "Pandora",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pandora.com"},
			},
		},
		{
			Name:     "Deezer",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deezer.com"},
			},
		},
		{
			Name:     "Tidal",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tidal.com"},
			},
		},
		{
			Name:     "QQ音乐",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "y.qq.com"},
			},
		},
		{
			Name:     "网易云音乐",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "music.163.com"},
			},
		},
		{
			Name:     "酷狗音乐",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kugou.com"},
			},
		},
		{
			Name:     "酷我音乐",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kuwo.cn"},
			},
		},
		{
			Name:     "虾米音乐",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xiami.com"},
			},
		},
		{
			Name:     "Bilibili",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bilibili.com"},
			},
		},
		{
			Name:     "Douyin",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "douyin.com"},
			},
		},
		{
			Name:     "TikTok",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tiktok.com"},
			},
		},
		{
			Name:     "Instagram",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "instagram.com"},
			},
		},
		{
			Name:     "Pinterest",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinterest.com"},
			},
		},
		{
			Name:     "Reddit",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "reddit.com"},
			},
		},
		{
			Name:     "IMDb",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "imdb.com"},
			},
		},
		{
			Name:     "Rotten Tomatoes",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rottentomatoes.com"},
			},
		},
		{
			Name:     "Letterboxd",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "letterboxd.com"},
			},
		},
		{
			Name:     "Metacritic",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "metacritic.com"},
			},
		},
		{
			Name:     "AllMusic",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "allmusic.com"},
			},
		},
		{
			Name:     "Bandcamp",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bandcamp.com"},
			},
		},
		{
			Name:     "Vimeo",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vimeo.com"},
			},
		},
		{
			Name:     "Dailymotion",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dailymotion.com"},
			},
		},
		{
			Name:     "Crunchyroll",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "crunchyroll.com"},
			},
		},
		{
			Name:     "Funimation",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "funimation.com"},
			},
		},
		{
			Name:     "Anime-Planet",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "anime-planet.com"},
			},
		},
		{
			Name:     "MyAnimeList",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "myanimelist.net"},
			},
		},
		{
			Name:     "Steam",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "store.steampowered.com"},
			},
		},
		{
			Name:     "Epic Games",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "epicgames.com"},
			},
		},
		{
			Name:     "Origin",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "origin.com"},
			},
		},
		{
			Name:     "GOG",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gog.com"},
			},
		},
		{
			Name:     "PlayStation",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "playstation.com"},
			},
		},
		{
			Name:     "Xbox",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xbox.com"},
			},
		},
		{
			Name:     "Nintendo",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nintendo.com"},
			},
		},
		{
			Name:     "Roblox",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "roblox.com"},
			},
		},
		{
			Name:     "Minecraft",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "minecraft.net"},
			},
		},
		{
			Name:     "Fortnite",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fortnite.com"},
			},
		},
		{
			Name:     "League of Legends",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "leagueoflegends.com"},
			},
		},
		{
			Name:     "Dota 2",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dota2.com"},
			},
		},
		{
			Name:     "Valorant",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "playvalorant.com"},
			},
		},
		{
			Name:     "CS2",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cs2.com"},
			},
		},
		{
			Name:     "Overwatch",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "overwatch.com"},
			},
		},
		{
			Name:     "Apex Legends",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apexlegends.com"},
			},
		},
		{
			Name:     "Discord",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discord.com"},
			},
		},
		{
			Name:     "Slack",
			Category: "Entertainment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "slack.com"},
			},
		},
		{
			Name:     "Amazon",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "amazon.com"},
				{Type: "header", Value: "x-amz-cf-id: .*"},
			},
		},
		{
			Name:     "eBay",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ebay.com"},
			},
		},
		{
			Name:     "Alibaba",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alibaba.com"},
			},
		},
		{
			Name:     "Taobao",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "taobao.com"},
			},
		},
		{
			Name:     "Tmall",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tmall.com"},
			},
		},
		{
			Name:     "JD.com",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jd.com"},
			},
		},
		{
			Name:     "Walmart",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "walmart.com"},
			},
		},
		{
			Name:     "Target",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "target.com"},
			},
		},
		{
			Name:     "Best Buy",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bestbuy.com"},
			},
		},
		{
			Name:     "Etsy",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "etsy.com"},
			},
		},
		{
			Name:     "Shopify",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopify.com"},
				{Type: "header", Value: "X-Shopify-Stage: .*"},
			},
		},
		{
			Name:     "Shopee",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopee.com"},
			},
		},
		{
			Name:     "Lazada",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lazada.com"},
			},
		},
		{
			Name:     "Rakuten",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rakuten.com"},
			},
		},
		{
			Name:     "Wish",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wish.com"},
			},
		},
		{
			Name:     "AliExpress",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aliexpress.com"},
			},
		},
		{
			Name:     "京东到家",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "daojia.jd.com"},
			},
		},
		{
			Name:     "拼多多",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinduoduo.com"},
			},
		},
		{
			Name:     "唯品会",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vip.com"},
			},
		},
		{
			Name:     "当当",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dangdang.com"},
			},
		},
		{
			Name:     "云集",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yunji.com"},
			},
		},
		{
			Name:     "有赞",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "youzan.com"},
			},
		},
		{
			Name:     "微店",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weidian.com"},
			},
		},
		{
			Name:     "抖音电商",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "douyin.com"},
			},
		},
		{
			Name:     "快手电商",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kuaishou.com"},
			},
		},
		{
			Name:     "网易严选",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yanxuan.com"},
			},
		},
		{
			Name:     "小米商城",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mi.com"},
			},
		},
		{
			Name:     "华为商城",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vmall.com"},
			},
		},
		{
			Name:     "Apple Store",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apple.com/shop"},
			},
		},
		{
			Name:     "Wayfair",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wayfair.com"},
			},
		},
		{
			Name:     "Overstock",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "overstock.com"},
			},
		},
		{
			Name:     "Zappos",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zappos.com"},
			},
		},
		{
			Name:     "ASOS",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "asos.com"},
			},
		},
		{
			Name:     "Zara",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zara.com"},
			},
		},
		{
			Name:     "H&M",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hm.com"},
			},
		},
		{
			Name:     "Uniqlo",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uniqlo.com"},
			},
		},
		{
			Name:     "Nike",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nike.com"},
			},
		},
		{
			Name:     "Adidas",
			Category: "E-commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "adidas.com"},
			},
		},
		{
			Name:     "Facebook",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "facebook.com"},
				{Type: "header", Value: "X-FB-Stats: .*"},
			},
		},
		{
			Name:     "Twitter",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "twitter.com"},
			},
		},
		{
			Name:     "LinkedIn",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin.com"},
			},
		},
		{
			Name:     "Instagram",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "instagram.com"},
			},
		},
		{
			Name:     "Snapchat",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "snapchat.com"},
			},
		},
		{
			Name:     "TikTok",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tiktok.com"},
			},
		},
		{
			Name:     "WeChat",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weixin.qq.com"},
			},
		},
		{
			Name:     "微博",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weibo.com"},
			},
		},
		{
			Name:     "知乎",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zhihu.com"},
			},
		},
		{
			Name:     "小红书",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xiaohongshu.com"},
			},
		},
		{
			Name:     "豆瓣",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "douban.com"},
			},
		},
		{
			Name:     "贴吧",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tieba.baidu.com"},
			},
		},
		{
			Name:     "B站",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bilibili.com"},
			},
		},
		{
			Name:     "抖音",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "douyin.com"},
			},
		},
		{
			Name:     "快手",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kuaishou.com"},
			},
		},
		{
			Name:     "陌陌",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "immomo.com"},
			},
		},
		{
			Name:     "探探",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tantanapp.com"},
			},
		},
		{
			Name:     "脉脉",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "maimai.cn"},
			},
		},
		{
			Name:     "领英",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin.com"},
			},
		},
		{
			Name:     "Tumblr",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tumblr.com"},
			},
		},
		{
			Name:     "Reddit",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "reddit.com"},
			},
		},
		{
			Name:     "Pinterest",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pinterest.com"},
			},
		},
		{
			Name:     "VKontakte",
			Category: "Social Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vk.com"},
			},
		},
		{
			Name:     "Telegram",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "telegram.org"},
			},
		},
		{
			Name:     "WhatsApp",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "whatsapp.com"},
			},
		},
		{
			Name:     "Zoom",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zoom.us"},
			},
		},
		{
			Name:     "Skype",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "skype.com"},
			},
		},
		{
			Name:     "Microsoft Teams",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "teams.microsoft.com"},
			},
		},
		{
			Name:     "Google Meet",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "meet.google.com"},
			},
		},
		{
			Name:     "钉钉",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dingtalk.com"},
			},
		},
		{
			Name:     "飞书",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "feishu.cn"},
			},
		},
		{
			Name:     "企业微信",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "work.weixin.qq.com"},
			},
		},
		{
			Name:     "QQ",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qq.com"},
			},
		},
		{
			Name:     "腾讯会议",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tencent.com"},
			},
		},
		{
			Name:     "Slack",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "slack.com"},
			},
		},
		{
			Name:     "Discord",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discord.com"},
			},
		},
		{
			Name:     "Viber",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "viber.com"},
			},
		},
		{
			Name:     "Line",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "line.me"},
			},
		},
		{
			Name:     "KakaoTalk",
			Category: "Communication",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kakaocorp.com"},
			},
		},
		{
			Name:     "Google",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "google.com"},
			},
		},
		{
			Name:     "Baidu",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "baidu.com"},
			},
		},
		{
			Name:     "Bing",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bing.com"},
			},
		},
		{
			Name:     "Yahoo",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yahoo.com"},
			},
		},
		{
			Name:     "DuckDuckGo",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "duckduckgo.com"},
			},
		},
		{
			Name:     "Yandex",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yandex.com"},
			},
		},
		{
			Name:     "搜狗搜索",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sogou.com"},
			},
		},
		{
			Name:     "神马搜索",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sm.cn"},
			},
		},
		{
			Name:     "360搜索",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "so.com"},
			},
		},
		{
			Name:     "GitHub",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "github.com"},
			},
		},
		{
			Name:     "GitLab",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gitlab.com"},
			},
		},
		{
			Name:     "Bitbucket",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bitbucket.org"},
			},
		},
		{
			Name:     "Stack Overflow",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stackoverflow.com"},
			},
		},
		{
			Name:     "Docker Hub",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hub.docker.com"},
			},
		},
		{
			Name:     "npm",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "npmjs.com"},
			},
		},
		{
			Name:     "PyPI",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pypi.org"},
			},
		},
		{
			Name:     "Cloudflare",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cf-ray: .*"},
			},
		},
		{
			Name:     "AWS",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-amz-cf-id: .*"},
			},
		},
		{
			Name:     "Google Cloud",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Google-.*"},
			},
		},
		{
			Name:     "Azure",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-azure-.*"},
			},
		},
		{
			Name:     "阿里云",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Cdn-Node: .*"},
			},
		},
		{
			Name:     "腾讯云",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Cdn-Request-ID: .*"},
			},
		},
		{
			Name:     "华为云",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "huaweicloud.com"},
			},
		},
		{
			Name:     "Akamai",
			Category: "Infrastructure",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Akamai-.*"},
			},
		},
		{
			Name:     "Google News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "news.google.com"},
			},
		},
		{
			Name:     "Apple News",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "apple.com/news"},
			},
		},
		{
			Name:     "Flipboard",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "flipboard.com"},
			},
		},
		{
			Name:     "Feedly",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "feedly.com"},
			},
		},
		{
			Name:     "今日头条",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "toutiao.com"},
			},
		},
		{
			Name:     "腾讯新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "news.qq.com"},
			},
		},
		{
			Name:     "网易新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "news.163.com"},
			},
		},
		{
			Name:     "搜狐新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "news.sohu.com"},
			},
		},
		{
			Name:     "新浪新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "news.sina.com.cn"},
			},
		},
		{
			Name:     "凤凰网",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ifeng.com"},
			},
		},
		{
			Name:     "环球网",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "huanqiu.com"},
			},
		},
		{
			Name:     "观察者网",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "guancha.cn"},
			},
		},
		{
			Name:     "澎湃新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thepaper.cn"},
			},
		},
		{
			Name:     "界面新闻",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jiemian.com"},
			},
		},
		{
			Name:     "财新",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "caixin.com"},
			},
		},
		{
			Name:     "36氪",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "36kr.com"},
			},
		},
		{
			Name:     "虎嗅",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "huxiu.com"},
			},
		},
		{
			Name:     "钛媒体",
			Category: "News Media",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tmtpost.com"},
			},
		},
		{
			Name:     "Google Analytics",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Google-.*"},
			},
		},
		{
			Name:     "Google AdSense",
			Category: "Advertising",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "googlesyndication.com"},
			},
		},
		{
			Name:     "Google AdSense",
			Category: "Advertising",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "googleadservices.com"},
			},
		},
		{
			Name:     "Facebook Pixel",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-FB-.*"},
			},
		},
		{
			Name:     "DoubleClick",
			Category: "Advertising",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-DoubleClick: .*"},
			},
		},
		{
			Name:     "Baidu Tongji",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hm.baidu.com"},
			},
		},
		{
			Name:     "CNZZ",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnzz.com"},
			},
		},
		{
			Name:     "GrowingIO",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "growingio.com"},
			},
		},
		{
			Name:     "神策数据",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sensorsdata.cn"},
			},
		},
		{
			Name:     "友盟+",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "umeng.com"},
			},
		},
		{
			Name:     "Hotjar",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hotjar.com"},
			},
		},
		{
			Name:     "Mixpanel",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mixpanel.com"},
			},
		},
		{
			Name:     "Amplitude",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "amplitude.com"},
			},
		},
		{
			Name:     "Segment",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "segment.com"},
			},
		},
		{
			Name:     "New Relic",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-NewRelic-.*"},
			},
		},
		{
			Name:     "Datadog",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "datadoghq.com"},
			},
		},
		{
			Name:     "Pingdom",
			Category: "Monitoring",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pingdom.com"},
			},
		},
		{
			Name:     "Cloudflare",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cf-ray: .*"},
			},
		},
		{
			Name:     "Akamai CDN",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Akamai-.*"},
			},
		},
		{
			Name:     "Fastly",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Fastly-.*"},
			},
		},
		{
			Name:     "CloudFront",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Amz-Cf-.*"},
			},
		},
		{
			Name:     "CDNJS",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cdnjs.com"},
			},
		},
		{
			Name:     "jsDelivr",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jsdelivr.com"},
			},
		},
		{
			Name:     "unpkg",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "unpkg.com"},
			},
		},
		{
			Name:     "GoDaddy",
			Category: "Domain Registrar",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "godaddy.com"},
			},
		},
		{
			Name:     "Namecheap",
			Category: "Domain Registrar",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "namecheap.com"},
			},
		},
		{
			Name:     "Name.com",
			Category: "Domain Registrar",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "name.com"},
			},
		},
		{
			Name:     "Domain.com",
			Category: "Domain Registrar",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "domain.com"},
			},
		},
		{
			Name:     "Hover",
			Category: "Domain Registrar",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hover.com"},
			},
		},
		{
			Name:     "Gandi",
			Category: "Domain Registrar",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gandi.net"},
			},
		},
		{
			Name:     "DNSPod",
			Category: "DNS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dnspod.cn"},
			},
		},
		{
			Name:     "Cloudflare DNS",
			Category: "DNS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cloudflare-dns.com"},
			},
		},
		{
			Name:     "阿里云解析",
			Category: "DNS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aliyun.com"},
			},
		},
		{
			Name:     "DynDNS",
			Category: "DNS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dyndns.org"},
			},
		},
		{
			Name:     "WP Engine",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-WPEngine: .*"},
			},
		},
		{
			Name:     "Kinsta",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kinsta.com"},
			},
		},
		{
			Name:     "Flywheel",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "getflywheel.com"},
			},
		},
		{
			Name:     "Pagely",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pagely.com"},
			},
		},
		{
			Name:     "SiteGround",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "siteground.com"},
			},
		},
		{
			Name:     "Bluehost",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bluehost.com"},
			},
		},
		{
			Name:     "HostGator",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hostgator.com"},
			},
		},
		{
			Name:     "InMotion Hosting",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "inmotionhosting.com"},
			},
		},
		{
			Name:     "DreamHost",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dreamhost.com"},
			},
		},
		{
			Name:     "A2 Hosting",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "a2hosting.com"},
			},
		},
		{
			Name:     "GreenGeeks",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "greengeeks.com"},
			},
		},
		{
			Name:     "Hostinger",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hostinger.com"},
			},
		},
		{
			Name:     "Site5",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "site5.com"},
			},
		},
		{
			Name:     "WebFaction",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "webfaction.com"},
			},
		},
		{
			Name:     "Linode",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linode.com"},
			},
		},
		{
			Name:     "DigitalOcean",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "digitalocean.com"},
			},
		},
		{
			Name:     "Vultr",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vultr.com"},
			},
		},
		{
			Name:     "AWS EC2",
			Category: "Hosting",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Amz-.*"},
			},
		},
		{
			Name:     "Heroku",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Heroku-.*"},
			},
		},
		{
			Name:     "Vercel",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vercel.com"},
			},
		},
		{
			Name:     "Netlify",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "netlify.com"},
			},
		},
		{
			Name:     "Render",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "render.com"},
			},
		},
		{
			Name:     "Railway",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "railway.app"},
			},
		},
		{
			Name:     "Fly.io",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fly.io"},
			},
		},
		{
			Name:     "Supabase",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "supabase.com"},
			},
		},
		{
			Name:     "Firebase",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "firebase.com"},
			},
		},
		{
			Name:     "Appwrite",
			Category: "PaaS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "appwrite.io"},
			},
		},
		{
			Name:     "Nginx",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Server: nginx.*"},
			},
			VersionRE: `nginx\/([0-9.]+)`,
		},
		{
			Name:     "Apache",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Server: Apache.*"},
			},
			VersionRE: `Apache\/([0-9.]+)`,
		},
		{
			Name:     "IIS",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Server: Microsoft-IIS.*"},
			},
			VersionRE: `Microsoft-IIS\/([0-9.]+)`,
		},
		{
			Name:     "LiteSpeed",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Server: LiteSpeed.*"},
			},
		},
		{
			Name:     "Caddy",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "Server: Caddy.*"},
			},
		},
		{
			Name:     "Node.js",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Powered-By: Express.*"},
			},
		},
		{
			Name:     "Cloudflare Workers",
			Category: "Serverless",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "CF-.*"},
			},
		},
		{
			Name:     "AWS Lambda",
			Category: "Serverless",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Amz-Invocation-Id: .*"},
			},
		},
		{
			Name:     "Google Cloud Functions",
			Category: "Serverless",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Google-.*"},
			},
		},
		{
			Name:     "Azure Functions",
			Category: "Serverless",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Azure-.*"},
			},
		},
		{
			Name:     "Salesforce",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "salesforce.com"},
			},
		},
		{
			Name:     "HubSpot",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hubspot.com"},
			},
		},
		{
			Name:     "Zoho CRM",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zoho.com/crm"},
			},
		},
		{
			Name:     "Pipedrive",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pipedrive.com"},
			},
		},
		{
			Name:     "Freshworks CRM",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "freshworks.com"},
			},
		},
		{
			Name:     "Insightly",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "insightly.com"},
			},
		},
		{
			Name:     "Copper",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "copper.com"},
			},
		},
		{
			Name:     "Netsuite",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "netsuite.com"},
			},
		},
		{
			Name:     "SAP CRM",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sap.com"},
			},
		},
		{
			Name:     "Oracle CRM",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "oracle.com"},
			},
		},
		{
			Name:     "Microsoft Dynamics",
			Category: "CRM",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dynamics.com"},
			},
		},
		{
			Name:     "Mailchimp",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mailchimp.com"},
			},
		},
		{
			Name:     "HubSpot Marketing",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hubspot.com"},
			},
		},
		{
			Name:     "Marketo",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "marketo.com"},
			},
		},
		{
			Name:     "Pardot",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pardot.com"},
			},
		},
		{
			Name:     "Eloqua",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "eloqua.com"},
			},
		},
		{
			Name:     "ActiveCampaign",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "activecampaign.com"},
			},
		},
		{
			Name:     "Sendinblue",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sendinblue.com"},
			},
		},
		{
			Name:     "ConvertKit",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "convertkit.com"},
			},
		},
		{
			Name:     "AWeber",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aweber.com"},
			},
		},
		{
			Name:     "GetResponse",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "getresponse.com"},
			},
		},
		{
			Name:     "MailerLite",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mailerlite.com"},
			},
		},
		{
			Name:     "Constant Contact",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "constantcontact.com"},
			},
		},
		{
			Name:     "Campaign Monitor",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "campaignmonitor.com"},
			},
		},
		{
			Name:     "Klaviyo",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "klaviyo.com"},
			},
		},
		{
			Name:     "丁香通",
			Category: "Marketing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dingxiangtong.com"},
			},
		},
		{
			Name:     "Jira",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "atlassian.net"},
			},
		},
		{
			Name:     "Trello",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trello.com"},
			},
		},
		{
			Name:     "Asana",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "asana.com"},
			},
		},
		{
			Name:     "Monday.com",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "monday.com"},
			},
		},
		{
			Name:     "Basecamp",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "basecamp.com"},
			},
		},
		{
			Name:     "Notion",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "notion.so"},
			},
		},
		{
			Name:     "ClickUp",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "clickup.com"},
			},
		},
		{
			Name:     "Wrike",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wrike.com"},
			},
		},
		{
			Name:     "Smartsheet",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "smartsheet.com"},
			},
		},
		{
			Name:     "Airtable",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airtable.com"},
			},
		},
		{
			Name:     "Zoho Projects",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zoho.com/projects"},
			},
		},
		{
			Name:     "Teamwork",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "teamwork.com"},
			},
		},
		{
			Name:     "Worktile",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "worktile.com"},
			},
		},
		{
			Name:     "Tapd",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tapd.cn"},
			},
		},
		{
			Name:     "禅道",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zentao.net"},
			},
		},
		{
			Name:     "Teambition",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "teambition.com"},
			},
		},
		{
			Name:     "Tower",
			Category: "Project Management",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tower.im"},
			},
		},
		{
			Name:     "蒲公英",
			Category: "Developer Tools",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pgyer.com"},
			},
		},
		{
			Name:     "Zendesk",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zendesk.com"},
			},
		},
		{
			Name:     "Freshdesk",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "freshdesk.com"},
			},
		},
		{
			Name:     "Intercom",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "intercom.com"},
			},
		},
		{
			Name:     "Drift",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drift.com"},
			},
		},
		{
			Name:     "LiveChat",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "livechat.com"},
			},
		},
		{
			Name:     "Olark",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "olark.com"},
			},
		},
		{
			Name:     "SnapEngage",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "snapengage.com"},
			},
		},
		{
			Name:     "Crisp",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "crisp.chat"},
			},
		},
		{
			Name:     "Tidio",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tidio.com"},
			},
		},
		{
			Name:     "Chatra",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chatra.io"},
			},
		},
		{
			Name:     "Pure Chat",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "purechat.com"},
			},
		},
		{
			Name:     "HubSpot Conversations",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hubspot.com"},
			},
		},
		{
			Name:     "Salesforce Service Cloud",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "salesforce.com"},
			},
		},
		{
			Name:     "Udesk",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "udesk.cn"},
			},
		},
		{
			Name:     "网易七鱼",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qi.163.com"},
			},
		},
		{
			Name:     "智齿科技",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sobot.com"},
			},
		},
		{
			Name:     "晓多客服",
			Category: "Customer Support",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xiaoduo.com"},
			},
		},
		{
			Name:     "AWS Cognito",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cognito-idp.amazonaws.com"},
			},
		},
		{
			Name:     "Auth0",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "auth0.com"},
			},
		},
		{
			Name:     "Okta",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "okta.com"},
			},
		},
		{
			Name:     "Ping Identity",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pingidentity.com"},
			},
		},
		{
			Name:     "OneLogin",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "onelogin.com"},
			},
		},
		{
			Name:     "Microsoft Entra ID",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "login.microsoftonline.com"},
			},
		},
		{
			Name:     "Google Identity",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "accounts.google.com"},
			},
		},
		{
			Name:     "Firebase Auth",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "firebase.google.com"},
			},
		},
		{
			Name:     "Supabase Auth",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "supabase.com"},
			},
		},
		{
			Name:     "Keycloak",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "keycloak.org"},
			},
		},
		{
			Name:     "Clerk",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "clerk.com"},
			},
		},
		{
			Name:     "NextAuth",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "next-auth.js.org"},
			},
		},
		{
			Name:     "Passport",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "passportjs.org"},
			},
		},
		{
			Name:     "Stormpath",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stormpath.com"},
			},
		},
		{
			Name:     "微信开放平台",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "open.weixin.qq.com"},
			},
		},
		{
			Name:     "支付宝开放平台",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alipay.com"},
			},
		},
		{
			Name:     "QQ登录",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "connect.qq.com"},
			},
		},
		{
			Name:     "新浪微博开放平台",
			Category: "Security",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "open.weibo.com"},
			},
		},
		{
			Name:     "Stripe",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stripe.com"},
			},
		},
		{
			Name:     "PayPal",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paypal.com"},
			},
		},
		{
			Name:     "Square",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "square.com"},
			},
		},
		{
			Name:     "Adyen",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "adyen.com"},
			},
		},
		{
			Name:     "Braintree",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "braintreepayments.com"},
			},
		},
		{
			Name:     "Authorize.net",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "authorizenet.com"},
			},
		},
		{
			Name:     "2Checkout",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "2checkout.com"},
			},
		},
		{
			Name:     "Worldpay",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "worldpay.com"},
			},
		},
		{
			Name:     "GlobalCollect",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "globalcollect.com"},
			},
		},
		{
			Name:     "Ingenico",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ingenico.com"},
			},
		},
		{
			Name:     "Verifone",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "verifone.com"},
			},
		},
		{
			Name:     "First Data",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "firstdata.com"},
			},
		},
		{
			Name:     "Elavon",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "elavon.com"},
			},
		},
		{
			Name:     "TSYS",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tsys.com"},
			},
		},
		{
			Name:     "Heartland Payment",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "heartlandpaymentsystems.com"},
			},
		},
		{
			Name:     "Chase Paymentech",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chasepaymentech.com"},
			},
		},
		{
			Name:     "NMI",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nmi.com"},
			},
		},
		{
			Name:     "PayU",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "payu.com"},
			},
		},
		{
			Name:     "Ally",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ally.com"},
			},
		},
		{
			Name:     "Klarna",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "klarna.com"},
			},
		},
		{
			Name:     "Afterpay",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "afterpay.com"},
			},
		},
		{
			Name:     "Affirm",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "affirm.com"},
			},
		},
		{
			Name:     "Sezzle",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sezzle.com"},
			},
		},
		{
			Name:     "QuadPay",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "quadpay.com"},
			},
		},
		{
			Name:     "Zip",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zip.co"},
			},
		},
		{
			Name:     "京东支付",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jd.com"},
			},
		},
		{
			Name:     "微信支付",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weixin.qq.com"},
			},
		},
		{
			Name:     "支付宝",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alipay.com"},
			},
		},
		{
			Name:     "银联",
			Category: "Payment Gateway",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "unionpay.com"},
			},
		},
		{
			Name:     "FedEx",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fedex.com"},
			},
		},
		{
			Name:     "UPS",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ups.com"},
			},
		},
		{
			Name:     "DHL",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dhl.com"},
			},
		},
		{
			Name:     "USPS",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "usps.com"},
			},
		},
		{
			Name:     "Royal Mail",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "royalmail.com"},
			},
		},
		{
			Name:     "Canada Post",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "canadapost.ca"},
			},
		},
		{
			Name:     "Australia Post",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "auspost.com.au"},
			},
		},
		{
			Name:     "EMS",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ems.com.cn"},
			},
		},
		{
			Name:     "顺丰速运",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sf-express.com"},
			},
		},
		{
			Name:     "中通快递",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zto.com"},
			},
		},
		{
			Name:     "圆通速递",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yto.com.cn"},
			},
		},
		{
			Name:     "韵达速递",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yundaex.com"},
			},
		},
		{
			Name:     "申通快递",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sto.cn"},
			},
		},
		{
			Name:     "百世汇通",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bestex.com"},
			},
		},
		{
			Name:     "菜鸟裹裹",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cainiao.com"},
			},
		},
		{
			Name:     "德邦物流",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deppon.com"},
			},
		},
		{
			Name:     "京东物流",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jd.com"},
			},
		},
		{
			Name:     "苏宁物流",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "suning.com"},
			},
		},
		{
			Name:     "亚马逊物流",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "amazon.com"},
			},
		},
		{
			Name:     "Uber Freight",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "uber.com"},
			},
		},
		{
			Name:     "DoorDash",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "doordash.com"},
			},
		},
		{
			Name:     "Uber Eats",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ubereats.com"},
			},
		},
		{
			Name:     "Grubhub",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "grubhub.com"},
			},
		},
		{
			Name:     "Postmates",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "postmates.com"},
			},
		},
		{
			Name:     "Deliveroo",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deliveroo.com"},
			},
		},
		{
			Name:     "Just Eat",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "just-eat.com"},
			},
		},
		{
			Name:     "饿了么",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ele.me"},
			},
		},
		{
			Name:     "美团外卖",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "meituan.com"},
			},
		},
		{
			Name:     "达达",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "imdada.cn"},
			},
		},
		{
			Name:     "闪送",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ishansong.com"},
			},
		},
		{
			Name:     "货拉拉",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "huolala.cn"},
			},
		},
		{
			Name:     "满帮集团",
			Category: "Logistics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "manbang.com"},
			},
		},
		{
			Name:     "Gmail",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mail.google.com"},
			},
		},
		{
			Name:     "Outlook",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "outlook.com"},
			},
		},
		{
			Name:     "Yahoo Mail",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mail.yahoo.com"},
			},
		},
		{
			Name:     "iCloud Mail",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "icloud.com"},
			},
		},
		{
			Name:     "QQ邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mail.qq.com"},
			},
		},
		{
			Name:     "163邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mail.163.com"},
			},
		},
		{
			Name:     "新浪邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mail.sina.com"},
			},
		},
		{
			Name:     "搜狐邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mail.sohu.com"},
			},
		},
		{
			Name:     "企业邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qiye.aliyun.com"},
			},
		},
		{
			Name:     "腾讯企业邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "exmail.qq.com"},
			},
		},
		{
			Name:     "网易企业邮箱",
			Category: "Email",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qiye.163.com"},
			},
		},
		{
			Name:     "SendGrid",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sendgrid.com"},
			},
		},
		{
			Name:     "Mailgun",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mailgun.com"},
			},
		},
		{
			Name:     "Mailchimp Transactional",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mailchimp.com"},
			},
		},
		{
			Name:     "Amazon SES",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aws.amazon.com/ses"},
			},
		},
		{
			Name:     "Postmark",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "postmarkapp.com"},
			},
		},
		{
			Name:     "SparkPost",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sparkpost.com"},
			},
		},
		{
			Name:     "Mandrill",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mandrill.com"},
			},
		},
		{
			Name:     "Mailjet",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mailjet.com"},
			},
		},
		{
			Name:     "Elastic Email",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "elasticemail.com"},
			},
		},
		{
			Name:     "SocketLabs",
			Category: "Email Service",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "socketlabs.com"},
			},
		},
		{
			Name:     "AWS S3",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "s3.amazonaws.com"},
			},
		},
		{
			Name:     "Google Cloud Storage",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "storage.googleapis.com"},
			},
		},
		{
			Name:     "Azure Blob Storage",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blob.core.windows.net"},
			},
		},
		{
			Name:     "Dropbox",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dropbox.com"},
			},
		},
		{
			Name:     "Google Drive",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drive.google.com"},
			},
		},
		{
			Name:     "OneDrive",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "onedrive.live.com"},
			},
		},
		{
			Name:     "Box",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "box.com"},
			},
		},
		{
			Name:     "iCloud",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "icloud.com"},
			},
		},
		{
			Name:     "Mega",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mega.nz"},
			},
		},
		{
			Name:     "pCloud",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pcloud.com"},
			},
		},
		{
			Name:     "Sync.com",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sync.com"},
			},
		},
		{
			Name:     "Tresorit",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tresorit.com"},
			},
		},
		{
			Name:     "坚果云",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jianguoyun.com"},
			},
		},
		{
			Name:     "百度网盘",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pan.baidu.com"},
			},
		},
		{
			Name:     "腾讯微云",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "weiyun.com"},
			},
		},
		{
			Name:     "阿里云盘",
			Category: "Storage",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aliyundrive.com"},
			},
		},
		{
			Name:     "MongoDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mongodb.com"},
			},
		},
		{
			Name:     "MySQL",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Mysql-.*"},
			},
		},
		{
			Name:     "PostgreSQL",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Postgres-.*"},
			},
		},
		{
			Name:     "Redis",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-Redis-.*"},
			},
		},
		{
			Name:     "Elasticsearch",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "elastic.co"},
			},
		},
		{
			Name:     "Neo4j",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "neo4j.com"},
			},
		},
		{
			Name:     "Cassandra",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cassandra.apache.org"},
			},
		},
		{
			Name:     "CockroachDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cockroachlabs.com"},
			},
		},
		{
			Name:     "Snowflake",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "snowflake.com"},
			},
		},
		{
			Name:     "BigQuery",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cloud.google.com/bigquery"},
			},
		},
		{
			Name:     "Redshift",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aws.amazon.com/redshift"},
			},
		},
		{
			Name:     "Databricks",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "databricks.com"},
			},
		},
		{
			Name:     "Cloudera",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cloudera.com"},
			},
		},
		{
			Name:     "Hadoop",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hadoop.apache.org"},
			},
		},
		{
			Name:     "Kafka",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kafka.apache.org"},
			},
		},
		{
			Name:     "RabbitMQ",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rabbitmq.com"},
			},
		},
		{
			Name:     "Oracle Database",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "oracle.com"},
			},
		},
		{
			Name:     "SQL Server",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-SQLServer-.*"},
			},
		},
		{
			Name:     "SQLite",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "X-SQLite-.*"},
			},
		},
		{
			Name:     "MariaDB",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mariadb.org"},
			},
		},
		{
			Name:     "Percona",
			Category: "Database",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "percona.com"},
			},
		},
		{
			Name:     "LegalZoom",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "legalzoom.com"},
			},
		},
		{
			Name:     "Rocket Lawyer",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rocketlawyer.com"},
			},
		},
		{
			Name:     "Nolo",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nolo.com"},
			},
		},
		{
			Name:     "Avvo",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "avvo.com"},
			},
		},
		{
			Name:     "FindLaw",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "findlaw.com"},
			},
		},
		{
			Name:     "LawInfo",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lawinfo.com"},
			},
		},
		{
			Name:     "Martindale",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "martindale.com"},
			},
		},
		{
			Name:     "Justia",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "justia.com"},
			},
		},
		{
			Name:     "Fastcase",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fastcase.com"},
			},
		},
		{
			Name:     "LexisNexis",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lexisnexis.com"},
			},
		},
		{
			Name:     "Westlaw",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "westlaw.com"},
			},
		},
		{
			Name:     "Thomson Reuters",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thomsonreuters.com"},
			},
		},
		{
			Name:     "律伴",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lvban.com"},
			},
		},
		{
			Name:     "找法网",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "findlaw.cn"},
			},
		},
		{
			Name:     "华律网",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "66law.cn"},
			},
		},
		{
			Name:     "法律快车",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lawtime.cn"},
			},
		},
		{
			Name:     "北大法宝",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pkulaw.cn"},
			},
		},
		{
			Name:     "威科先行",
			Category: "Legal",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wkinfo.com.cn"},
			},
		},
		{
			Name:     "汇量科技",
			Category: "Compliance",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mininglamp.com"},
			},
		},
		{
			Name:     "LinkedIn",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin.com"},
			},
		},
		{
			Name:     "Indeed",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "indeed.com"},
			},
		},
		{
			Name:     "Glassdoor",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "glassdoor.com"},
			},
		},
		{
			Name:     "Monster",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "monster.com"},
			},
		},
		{
			Name:     "CareerBuilder",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "careerbuilder.com"},
			},
		},
		{
			Name:     "ZipRecruiter",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ziprecruiter.com"},
			},
		},
		{
			Name:     "Seek",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "seek.com"},
			},
		},
		{
			Name:     "Job.com",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "job.com"},
			},
		},
		{
			Name:     "Simply Hired",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "simplyhired.com"},
			},
		},
		{
			Name:     "Snagajob",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "snagajob.com"},
			},
		},
		{
			Name:     "Workday",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "workday.com"},
			},
		},
		{
			Name:     "SAP SuccessFactors",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "successfactors.com"},
			},
		},
		{
			Name:     "BambooHR",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bamboohr.com"},
			},
		},
		{
			Name:     "ADP",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "adp.com"},
			},
		},
		{
			Name:     "Paycom",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paycom.com"},
			},
		},
		{
			Name:     "Paylocity",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "paylocity.com"},
			},
		},
		{
			Name:     "UltiPro",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ultipro.com"},
			},
		},
		{
			Name:     "Cornerstone OnDemand",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "csod.com"},
			},
		},
		{
			Name:     "Kronos",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kronos.com"},
			},
		},
		{
			Name:     "Namely",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "namely.com"},
			},
		},
		{
			Name:     "Gusto",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gusto.com"},
			},
		},
		{
			Name:     "Zenefits",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zenefits.com"},
			},
		},
		{
			Name:     "Rippling",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rippling.com"},
			},
		},
		{
			Name:     "Freshteam",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "freshteam.com"},
			},
		},
		{
			Name:     "拉勾网",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lagou.com"},
			},
		},
		{
			Name:     "Boss直聘",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zhipin.com"},
			},
		},
		{
			Name:     "智联招聘",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zhaopin.com"},
			},
		},
		{
			Name:     "前程无忧",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "51job.com"},
			},
		},
		{
			Name:     "猎聘网",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "liepin.com"},
			},
		},
		{
			Name:     "58同城",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "58.com"},
			},
		},
		{
			Name:     "赶集网",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ganji.com"},
			},
		},
		{
			Name:     "脉脉招聘",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "maimai.cn"},
			},
		},
		{
			Name:     "LinkedIn 招聘",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linkedin.com"},
			},
		},
		{
			Name:     "科锐国际",
			Category: "HR",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "careerfrog.com.cn"},
			},
		},
		{
			Name:     "Fannie Mae",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fanniemae.com"},
			},
		},
		{
			Name:     "Freddie Mac",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "freddiemac.com"},
			},
		},
		{
			Name:     "Zillow Group",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zillow.com"},
			},
		},
		{
			Name:     "Redfin",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "redfin.com"},
			},
		},
		{
			Name:     "Realtor.com",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "realtor.com"},
			},
		},
		{
			Name:     "Homes.com",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "homes.com"},
			},
		},
		{
			Name:     "Trulia",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "trulia.com"},
			},
		},
		{
			Name:     "MLS",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mls.com"},
			},
		},
		{
			Name:     "Coldwell Banker",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coldwellbanker.com"},
			},
		},
		{
			Name:     "Century 21",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "century21.com"},
			},
		},
		{
			Name:     "Sotheby's",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sothebysrealty.com"},
			},
		},
		{
			Name:     "Christie's",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "christies.com"},
			},
		},
		{
			Name:     "Compass",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "compass.com"},
			},
		},
		{
			Name:     "Keller Williams",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kellerwilliams.com"},
			},
		},
		{
			Name:     "RE/MAX",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "remax.com"},
			},
		},
		{
			Name:     "贝壳找房",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ke.com"},
			},
		},
		{
			Name:     "链家",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lianjia.com"},
			},
		},
		{
			Name:     "自如",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ziroom.com"},
			},
		},
		{
			Name:     "蛋壳公寓",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "danke.com"},
			},
		},
		{
			Name:     "青客",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qkys.com"},
			},
		},
		{
			Name:     "万科物业",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vanke.com"},
			},
		},
		{
			Name:     "碧桂园服务",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bgy.com.cn"},
			},
		},
		{
			Name:     "龙湖智慧服务",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "longfor.com"},
			},
		},
		{
			Name:     "绿城服务",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lvyec.com"},
			},
		},
		{
			Name:     "58同城房产",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "58.com"},
			},
		},
		{
			Name:     "安居客",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "anjuke.com"},
			},
		},
		{
			Name:     "房天下",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fang.com"},
			},
		},
		{
			Name:     "搜房网",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "soufun.com"},
			},
		},
		{
			Name:     "乐居",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "leju.com"},
			},
		},
		{
			Name:     "贝壳新房",
			Category: "Real Estate",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ke.com"},
			},
		},
		{
			Name:     "土巴兔",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "to8to.com"},
			},
		},
		{
			Name:     "齐家网",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jia.com"},
			},
		},
		{
			Name:     "装修之家",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zx123.com"},
			},
		},
		{
			Name:     "我要装修网",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "51zhuangxiu.com"},
			},
		},
		{
			Name:     "太平洋家居",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jiaju.com"},
			},
		},
		{
			Name:     "Homify",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "homify.com"},
			},
		},
		{
			Name:     "Houzz",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "houzz.com"},
			},
		},
		{
			Name:     "Porch",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "porch.com"},
			},
		},
		{
			Name:     "Angi",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "angi.com"},
			},
		},
		{
			Name:     "Thumbtack",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thumbtack.com"},
			},
		},
		{
			Name:     "TaskRabbit",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "taskrabbit.com"},
			},
		},
		{
			Name:     "HomeAdvisor",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "homeadvisor.com"},
			},
		},
		{
			Name:     "Bark",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bark.com"},
			},
		},
		{
			Name:     "Star of Service",
			Category: "Construction",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "starofservice.com"},
			},
		},
		{
			Name:     "John Deere",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "deere.com"},
			},
		},
		{
			Name:     "AGCO",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "agcocorp.com"},
			},
		},
		{
			Name:     "Case IH",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "caseih.com"},
			},
		},
		{
			Name:     "New Holland",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "newholland.com"},
			},
		},
		{
			Name:     "Kubota",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kubota.com"},
			},
		},
		{
			Name:     "Massey Ferguson",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "masseyferguson.com"},
			},
		},
		{
			Name:     "Claas",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "claas.com"},
			},
		},
		{
			Name:     "Same Deutz-Fahr",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "samegroupt.com"},
			},
		},
		{
			Name:     "Valley Irrigation",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "valleyirrigation.com"},
			},
		},
		{
			Name:     "Lindsay Corporation",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lindsay.com"},
			},
		},
		{
			Name:     "Jain Irrigation",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jains.com"},
			},
		},
		{
			Name:     "Nutrien",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nutrien.com"},
			},
		},
		{
			Name:     "Mosaic",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mosaicco.com"},
			},
		},
		{
			Name:     "CF Industries",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cfindustries.com"},
			},
		},
		{
			Name:     "Yara International",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yara.com"},
			},
		},
		{
			Name:     "BASF",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "basf.com"},
			},
		},
		{
			Name:     "Syngenta",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "syngenta.com"},
			},
		},
		{
			Name:     "Bayer Crop Science",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cropscience.bayer.com"},
			},
		},
		{
			Name:     "Corteva",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "corteva.com"},
			},
		},
		{
			Name:     "FMC Corporation",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fmc.com"},
			},
		},
		{
			Name:     "先正达",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "syngenta.com.cn"},
			},
		},
		{
			Name:     "拜耳作物科学",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cropscience.bayer.com.cn"},
			},
		},
		{
			Name:     "巴斯夫",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "basf.com.cn"},
			},
		},
		{
			Name:     "隆平高科",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lpht.com.cn"},
			},
		},
		{
			Name:     "登海种业",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "denghai.com"},
			},
		},
		{
			Name:     "丰乐种业",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fleming.com.cn"},
			},
		},
		{
			Name:     "大北农",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dabeinong.com"},
			},
		},
		{
			Name:     "牧原食品",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "muyuanfood.com"},
			},
		},
		{
			Name:     "温氏股份",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wenshiyi.com"},
			},
		},
		{
			Name:     "双汇发展",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shuanghui.net"},
			},
		},
		{
			Name:     "伊利集团",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "yili.com"},
			},
		},
		{
			Name:     "蒙牛集团",
			Category: "Agriculture",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mengniu.com"},
			},
		},
		{
			Name:     "三聚环保",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sanjiu.cc"},
			},
		},
		{
			Name:     "Carbon",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "carbon.com"},
			},
		},
		{
			Name:     "Climeworks",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "climeworks.com"},
			},
		},
		{
			Name:     "Carbon Clean",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "carbonclean.com"},
			},
		},
		{
			Name:     "CarbonCure",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "carboncure.com"},
			},
		},
		{
			Name:     "Direct Air Capture",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "directaircapture.com"},
			},
		},
		{
			Name:     "Occidental",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "oxy.com"},
			},
		},
		{
			Name:     "Air Liquide",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airliquide.com"},
			},
		},
		{
			Name:     "Linde",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "linde.com"},
			},
		},
		{
			Name:     "Air Products",
			Category: "Environment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airproducts.com"},
			},
		},
		{
			Name:     "Boeing",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "boeing.com"},
			},
		},
		{
			Name:     "Airbus",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "airbus.com"},
			},
		},
		{
			Name:     "Lockheed Martin",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lockheedmartin.com"},
			},
		},
		{
			Name:     "Northrop Grumman",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "northropgrumman.com"},
			},
		},
		{
			Name:     "Raytheon Technologies",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "raytheon.com"},
			},
		},
		{
			Name:     "GE Aviation",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "geaviation.com"},
			},
		},
		{
			Name:     "Rolls-Royce",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rolls-royce.com"},
			},
		},
		{
			Name:     "Pratt & Whitney",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prattwhitney.com"},
			},
		},
		{
			Name:     "CFM International",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cfmaero.com"},
			},
		},
		{
			Name:     "Honeywell Aerospace",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "honeywell.com"},
			},
		},
		{
			Name:     "Collins Aerospace",
			Category: "Aviation",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "collinsaerospace.com"},
			},
		},
		{
			Name:     "SpaceX",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "spacex.com"},
			},
		},
		{
			Name:     "Blue Origin",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blueorigin.com"},
			},
		},
		{
			Name:     "Virgin Galactic",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "virgingalactic.com"},
			},
		},
		{
			Name:     "Rocket Lab",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rocketlabusa.com"},
			},
		},
		{
			Name:     "Sierra Space",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sierraspace.com"},
			},
		},
		{
			Name:     "Relativity Space",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "relativityspace.com"},
			},
		},
		{
			Name:     "Axiom Space",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "axiomspace.com"},
			},
		},
		{
			Name:     "SpaceX Starlink",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "starlink.com"},
			},
		},
		{
			Name:     "OneWeb",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "oneweb.net"},
			},
		},
		{
			Name:     "Planet Labs",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "planet.com"},
			},
		},
		{
			Name:     "Maxar Technologies",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "maxar.com"},
			},
		},
		{
			Name:     "BlackSky",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "blacksky.com"},
			},
		},
		{
			Name:     "Exolaunch",
			Category: "Aerospace",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "exolaunch.com"},
			},
		},
		{
			Name:     "ExxonMobil",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "exxonmobil.com"},
			},
		},
		{
			Name:     "Saudi Aramco",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "aramco.com"},
			},
		},
		{
			Name:     "Royal Dutch Shell",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shell.com"},
			},
		},
		{
			Name:     "BP",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bp.com"},
			},
		},
		{
			Name:     "Chevron",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chevron.com"},
			},
		},
		{
			Name:     "TotalEnergies",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "totalenergies.com"},
			},
		},
		{
			Name:     "ConocoPhillips",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "conocophillips.com"},
			},
		},
		{
			Name:     "Eni",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "eni.com"},
			},
		},
		{
			Name:     "Repsol",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "repsol.com"},
			},
		},
		{
			Name:     "Petrobras",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "petrobras.com"},
			},
		},
		{
			Name:     "Rosneft",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rosneft.com"},
			},
		},
		{
			Name:     "Gazprom",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gazprom.com"},
			},
		},
		{
			Name:     "Lukoil",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lukoil.com"},
			},
		},
		{
			Name:     "中国石油",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnpc.com.cn"},
			},
		},
		{
			Name:     "中国石化",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "sinopec.com"},
			},
		},
		{
			Name:     "中国海油",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnooc.com.cn"},
			},
		},
		{
			Name:     "中国神华",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shenhua.com"},
			},
		},
		{
			Name:     "陕西煤业",
			Category: "Energy",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shanximei.com"},
			},
		},
		{
			Name:     "Tiffany & Co.",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tiffany.com"},
			},
		},
		{
			Name:     "Cartier",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cartier.com"},
			},
		},
		{
			Name:     "Van Cleef & Arpels",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vancleefarpels.com"},
			},
		},
		{
			Name:     "Bulgari",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bulgari.com"},
			},
		},
		{
			Name:     "Harry Winston",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "harrywinston.com"},
			},
		},
		{
			Name:     "Graff",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "graff.com"},
			},
		},
		{
			Name:     "De Beers",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "debeers.com"},
			},
		},
		{
			Name:     "Pandora",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "pandora.com"},
			},
		},
		{
			Name:     "Swatch",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "swatch.com"},
			},
		},
		{
			Name:     "Swarovski",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "swarovski.com"},
			},
		},
		{
			Name:     "周大福",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chowtaifook.com"},
			},
		},
		{
			Name:     "周生生",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chowsang.com"},
			},
		},
		{
			Name:     "六福珠宝",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lukfook.com"},
			},
		},
		{
			Name:     "老凤祥",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lafx.com"},
			},
		},
		{
			Name:     "潮宏基",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chljs.com"},
			},
		},
		{
			Name:     "明牌珠宝",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mingr.com"},
			},
		},
		{
			Name:     "周大生",
			Category: "Jewelry",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zds.com"},
			},
		},
		{
			Name:     "Louis Vuitton",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "louisvuitton.com"},
			},
		},
		{
			Name:     "Gucci",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "gucci.com"},
			},
		},
		{
			Name:     "Prada",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prada.com"},
			},
		},
		{
			Name:     "Hermès",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hermes.com"},
			},
		},
		{
			Name:     "Burberry",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "burberry.com"},
			},
		},
		{
			Name:     "Dior",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dior.com"},
			},
		},
		{
			Name:     "Chanel",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chanel.com"},
			},
		},
		{
			Name:     "Versace",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "versace.com"},
			},
		},
		{
			Name:     "Fendi",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fendi.com"},
			},
		},
		{
			Name:     "Armani",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "armani.com"},
			},
		},
		{
			Name:     "Valentino",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "valentino.com"},
			},
		},
		{
			Name:     "Ralph Lauren",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ralphlauren.com"},
			},
		},
		{
			Name:     "Michael Kors",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "michaelkors.com"},
			},
		},
		{
			Name:     "Coach",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "coach.com"},
			},
		},
		{
			Name:     "Tory Burch",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "toryburch.com"},
			},
		},
		{
			Name:     "Kate Spade",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "katespade.com"},
			},
		},
		{
			Name:     "Longchamp",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "longchamp.com"},
			},
		},
		{
			Name:     "Mulberry",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mulberry.com"},
			},
		},
		{
			Name:     "MCM",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mcmworldwide.com"},
			},
		},
		{
			Name:     "Rolex",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rolex.com"},
			},
		},
		{
			Name:     "Omega",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "omega.com"},
			},
		},
		{
			Name:     "Patek Philippe",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "patek.com"},
			},
		},
		{
			Name:     "Audemars Piguet",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "audemarspiguet.com"},
			},
		},
		{
			Name:     "Tag Heuer",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "tagheuer.com"},
			},
		},
		{
			Name:     "IWC",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "iwc.com"},
			},
		},
		{
			Name:     "Breitling",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "breitling.com"},
			},
		},
		{
			Name:     "Cartier Watches",
			Category: "Luxury",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cartier.com"},
			},
		},
		{
			Name:     "Philip Morris",
			Category: "Tobacco",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "philipmorris.com"},
			},
		},
		{
			Name:     "Altria",
			Category: "Tobacco",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "altria.com"},
			},
		},
		{
			Name:     "British American Tobacco",
			Category: "Tobacco",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bat.com"},
			},
		},
		{
			Name:     "Imperial Brands",
			Category: "Tobacco",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "imperialbrandsplc.com"},
			},
		},
		{
			Name:     "Japan Tobacco",
			Category: "Tobacco",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jti.com"},
			},
		},
		{
			Name:     "KT&G",
			Category: "Tobacco",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ktng.com"},
			},
		},
		{
			Name:     "PetSmart",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "petsmart.com"},
			},
		},
		{
			Name:     "Petco",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "petco.com"},
			},
		},
		{
			Name:     "Chewy",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "chewy.com"},
			},
		},
		{
			Name:     "PetFlow",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "petflow.com"},
			},
		},
		{
			Name:     "1-800-PetMeds",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "1800petmeds.com"},
			},
		},
		{
			Name:     "VetRxDirect",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vetrxdirect.com"},
			},
		},
		{
			Name:     "Pets at Home",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "petsathome.com"},
			},
		},
		{
			Name:     "Zooplus",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zooplus.com"},
			},
		},
		{
			Name:     "Fressnapf",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "fressnapf.com"},
			},
		},
		{
			Name:     "Petsense",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "petsense.com"},
			},
		},
		{
			Name:     "波奇网",
			Category: "Pet",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "boqii.com"},
			},
		},
		{
			Name:     "Etsy",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "etsy.com"},
			},
		},
		{
			Name:     "Amazon Books",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "amazon.com"},
			},
		},
		{
			Name:     "Barnes & Noble",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "barnesandnoble.com"},
			},
		},
		{
			Name:     "Books-A-Million",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "booksamillion.com"},
			},
		},
		{
			Name:     "IndieBound",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "indiebound.org"},
			},
		},
		{
			Name:     "Alibris",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "alibris.com"},
			},
		},
		{
			Name:     "Better World Books",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "betterworldbooks.com"},
			},
		},
		{
			Name:     "ThriftBooks",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "thriftbooks.com"},
			},
		},
		{
			Name:     "World of Books",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "worldofbooks.com"},
			},
		},
		{
			Name:     "京东图书",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jd.com"},
			},
		},
		{
			Name:     "当当",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dangdang.com"},
			},
		},
		{
			Name:     "亚马逊中国",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "amazon.cn"},
			},
		},
		{
			Name:     "中国图书网",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bookschina.com"},
			},
		},
		{
			Name:     "蔚蓝书店",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bookuu.com"},
			},
		},
		{
			Name:     "Kindle",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kindle.com"},
			},
		},
		{
			Name:     "Kobo",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "kobo.com"},
			},
		},
		{
			Name:     "Nook",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "nook.com"},
			},
		},
		{
			Name:     "Google Books",
			Category: "Books",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "books.google.com"},
			},
		},
		{
			Name:     "Audible",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "audible.com"},
			},
		},
		{
			Name:     "Audiobooks.com",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "audiobooks.com"},
			},
		},
		{
			Name:     "Scribd",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "scribd.com"},
			},
		},
		{
			Name:     "BookBub",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bookbub.com"},
			},
		},
		{
			Name:     "Goodreads",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "goodreads.com"},
			},
		},
		{
			Name:     "Shelfari",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shelfari.com"},
			},
		},
		{
			Name:     "LibraryThing",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "librarything.com"},
			},
		},
		{
			Name:     "豆瓣读书",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "book.douban.com"},
			},
		},
		{
			Name:     "起点中文网",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "qidian.com"},
			},
		},
		{
			Name:     "晋江文学城",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jjwxc.net"},
			},
		},
		{
			Name:     "纵横中文网",
			Category: "Publishing",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "zongheng.com"},
			},
		},
		{
			Name:     "3M",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "3m.com"},
			},
		},
		{
			Name:     "Honeywell",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "honeywell.com"},
			},
		},
		{
			Name:     "General Electric",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ge.com"},
			},
		},
		{
			Name:     "Siemens",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "siemens.com"},
			},
		},
		{
			Name:     "Bosch",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bosch.com"},
			},
		},
		{
			Name:     "ABB",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "abb.com"},
			},
		},
		{
			Name:     "Schneider Electric",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "se.com"},
			},
		},
		{
			Name:     "Emerson Electric",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "emerson.com"},
			},
		},
		{
			Name:     "Eaton",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "eaton.com"},
			},
		},
		{
			Name:     "Caterpillar",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cat.com"},
			},
		},
		{
			Name:     "Komatsu",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "komatsu.com"},
			},
		},
		{
			Name:     "Hitachi",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hitachi.com"},
			},
		},
		{
			Name:     "Mitsubishi Electric",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mitsubishielectric.com"},
			},
		},
		{
			Name:     "Ingersoll Rand",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "ingersollrand.com"},
			},
		},
		{
			Name:     "Rockwell Automation",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "rockwellautomation.com"},
			},
		},
		{
			Name:     "Xylem",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xylem.com"},
			},
		},
		{
			Name:     "Illinois Tool Works",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "itw.com"},
			},
		},
		{
			Name:     "Stanley Black & Decker",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "stanleyblackanddecker.com"},
			},
		},
		{
			Name:     "Avery Dennison",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "averydennison.com"},
			},
		},
		{
			Name:     "Parker Hannifin",
			Category: "Industrial",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "parker.com"},
			},
		},
		{
			Name:     "Epson",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "epson.com"},
			},
		},
		{
			Name:     "Canon",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "canon.com"},
			},
		},
		{
			Name:     "Brother",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "brother.com"},
			},
		},
		{
			Name:     "Lexmark",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lexmark.com"},
			},
		},
		{
			Name:     "Xerox",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "xerox.com"},
			},
		},
		{
			Name:     "HP",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hp.com"},
			},
		},
		{
			Name:     "Dell",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "dell.com"},
			},
		},
		{
			Name:     "Lenovo",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "lenovo.com"},
			},
		},
		{
			Name:     "Microsoft",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "microsoft.com"},
			},
		},
		{
			Name:     "Logitech",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "logitech.com"},
			},
		},
		{
			Name:     "Plantronics",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "poly.com"},
			},
		},
		{
			Name:     "Jabra",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jabra.com"},
			},
		},
		{
			Name:     "Cisco",
			Category: "Office Equipment",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cisco.com"},
			},
		},
	}

	for _, fp := range whatWebDB {
		FingerprintDB = append(FingerprintDB, fp)
	}
}

func AddWhatWebFingerprintsToDB() {
	initWhatWebFingerprints()
}
