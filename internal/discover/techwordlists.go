// Tech-specific smart wordlists: when hellhound detects a specific framework
// (WordPress, Django, Rails, Laravel, Spring, Drupal, Joomla), auto-inject a
// small, curated wordlist of paths that only matter for that stack. This
// turns a one-size-fits-all fuzz into a targeted one: a Rails target
// instantly gets /rails/info/routes probed, a Spring target gets /actuator/*,
// a WordPress target gets /wp-admin, /wp-login.php, /xmlrpc.php, etc.
//
// Detection is cheap: it uses signals the discovery phase has already
// collected (homepage body, response headers, meta tags) and doesn't send
// any extra requests of its own.
package discover

import (
	"bytes"
	"context"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// Tech is a detected technology that gates one or more tech-specific
// wordlists.
type Tech string

const (
	TechWordPress Tech = "wordpress"
	TechDrupal    Tech = "drupal"
	TechJoomla    Tech = "joomla"
	TechDjango    Tech = "django"
	TechRails     Tech = "rails"
	TechLaravel   Tech = "laravel"
	TechSpring    Tech = "spring"
	TechPHP       Tech = "php"
	TechNodeJS    Tech = "nodejs"
	TechAspNet    Tech = "aspnet"
)

// techFingerprints lets DetectTech decide which stacks a target is running
// based on body/header signals from the homepage.
type techFingerprint struct {
	Tech       Tech
	BodyNeedle []string          // ANY present in body counts
	Headers    map[string]string // header-name -> substring-of-value; ANY match counts
}

var fingerprints = []techFingerprint{
	{TechWordPress, []string{"/wp-content/", "/wp-includes/", "wp-emoji", "WordPress"}, map[string]string{"x-powered-by": "WordPress", "link": "wp-json"}},
	{TechDrupal, []string{"Drupal.settings", "sites/all/", "sites/default/"}, map[string]string{"x-drupal-cache": "", "x-generator": "Drupal"}},
	{TechJoomla, []string{"/media/jui/", "Joomla!", "/components/com_"}, map[string]string{"x-generator": "Joomla"}},
	{TechDjango, []string{"csrfmiddlewaretoken", "__admin_media_prefix__"}, map[string]string{}},
	{TechRails, []string{"csrf-param\" content=\"authenticity_token", "rails-ujs"}, map[string]string{"x-powered-by": "Phusion Passenger", "x-rails-version": ""}},
	{TechLaravel, []string{"laravel_session", "XSRF-TOKEN"}, map[string]string{"set-cookie": "laravel_session"}},
	{TechSpring, []string{"Whitelabel Error Page", "spring.io"}, map[string]string{"x-application-context": ""}},
	{TechPHP, []string{"<?php", ".php?"}, map[string]string{"x-powered-by": "PHP"}},
	{TechNodeJS, []string{}, map[string]string{"x-powered-by": "Express"}},
	{TechAspNet, []string{"__VIEWSTATE", "__EVENTVALIDATION"}, map[string]string{"x-powered-by": "ASP.NET", "x-aspnet-version": ""}},
}

// DetectTech probes the target's homepage ONCE (reusing the same request a
// full discovery run would do anyway) and returns the set of technologies
// its body/headers fingerprint as. Returns nil on any failure — tech
// detection is best-effort and never fatal.
func DetectTech(ctx context.Context, eng *engine.Engine, baseURL string) []Tech {
	resps := eng.DoAll(ctx, []engine.Request{{Method: "GET", URL: baseURL + "/"}})
	if len(resps) != 1 || resps[0].Err != nil {
		return nil
	}
	resp := resps[0]
	return matchFingerprints(resp.Body, resp.Header)
}

// matchFingerprints runs each registered fingerprint against the given body
// and headers. Separated from DetectTech for easy unit testing — no network.
func matchFingerprints(body []byte, header map[string][]string) []Tech {
	var out []Tech
	for _, fp := range fingerprints {
		if matchesTech(body, header, fp) {
			out = append(out, fp.Tech)
		}
	}
	return out
}

func matchesTech(body []byte, header map[string][]string, fp techFingerprint) bool {
	for _, n := range fp.BodyNeedle {
		if bytes.Contains(body, []byte(n)) {
			return true
		}
	}
	for hName, hSub := range fp.Headers {
		for storedName, vs := range header {
			if !strings.EqualFold(storedName, hName) {
				continue
			}
			for _, v := range vs {
				if hSub == "" || strings.Contains(strings.ToLower(v), strings.ToLower(hSub)) {
					return true
				}
			}
		}
	}
	return false
}

// techWords is the per-stack wordlist. Kept small and surgical — these
// supplement, not replace, the main wordlist. Every entry is a path commonly
// used by that stack and rarely used by anything else, so hits are high-
// signal.
var techWords = map[Tech][]string{
	TechWordPress: {
		"wp-admin", "wp-login.php", "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
		"xmlrpc.php", "wp-cron.php", "wp-content", "wp-content/plugins", "wp-content/uploads",
		"wp-content/debug.log", "wp-json", "wp-json/wp/v2/users", "wp-admin/admin-ajax.php",
		"wp-admin/install.php", "wp-admin/upgrade.php", "wp-trackback.php",
	},
	TechDrupal: {
		"user/login", "user/register", "user/password", "admin", "admin/config",
		"CHANGELOG.txt", "update.php", "install.php", "node/1", "?q=user",
	},
	TechJoomla: {
		"administrator", "administrator/index.php", "administrator/manifests",
		"configuration.php", "configuration.php.bak", "cache/", "logs/", "tmp/",
	},
	TechDjango: {
		"admin", "admin/login", "admin/password_reset", "accounts/login", "accounts/password_reset",
		"__debug__", "static/admin/", "api-auth", "swagger", "redoc",
	},
	TechRails: {
		"rails/info/routes", "rails/info/properties", "rails/mailers", "rails/db",
		"assets", "config/database.yml", "config/secrets.yml", "config/master.key",
		"log/development.log", "log/production.log",
	},
	TechLaravel: {
		"telescope", "horizon", "nova", ".env", "storage/logs/laravel.log",
		"vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "_ignition/execute-solution",
		"_ignition/health-check", "api/documentation",
	},
	TechSpring: {
		"actuator", "actuator/health", "actuator/env", "actuator/beans", "actuator/mappings",
		"actuator/heapdump", "actuator/trace", "actuator/httptrace", "actuator/metrics",
		"actuator/loggers", "actuator/threaddump", "actuator/configprops", "api-docs",
		"swagger-ui.html", "v2/api-docs", "v3/api-docs",
	},
	TechPHP: {
		"info.php", "phpinfo.php", "test.php", "config.php", "config.php.bak",
		"debug.php", "shell.php", "upload.php",
	},
	TechNodeJS: {
		".env", "package.json", "package-lock.json", "yarn.lock", "node_modules",
		"server.js", "app.js", "config.json",
	},
	TechAspNet: {
		"trace.axd", "elmah.axd", "web.config", "web.config.bak",
		"ScriptResource.axd", "WebResource.axd", "Reserved.ReportViewerWebControl.axd",
	},
}

// WordsForTechs returns the deduplicated union of tech-specific words for
// the given stacks. Caller merges the result into the main wordlist.
func WordsForTechs(techs []Tech) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range techs {
		for _, w := range techWords[t] {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}
