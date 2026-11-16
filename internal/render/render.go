// Package render gets the DOM of a page AFTER its JavaScript has run, by
// driving a Chrome/Chromium that is already installed on the machine in
// headless mode. A single-page app's static HTML is an empty shell; its
// links only exist once the scripts have built the page. No browser is
// bundled or downloaded and no Go dependency is added: this package only
// starts the local binary with --dump-dom and reads its output.
package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// candidates are the executable names tried, in order, when no path is given.
var candidates = []string{
	"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
	"chrome", "microsoft-edge", "brave-browser",
}

// Find returns the path of a usable browser binary. explicit, when set,
// must exist; otherwise PATH and a few well-known locations are searched.
func Find(explicit string) (string, error) {
	if explicit != "" {
		if p, err := exec.LookPath(explicit); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("browser %q not found", explicit)
	}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("no Chrome/Chromium found (install one, or pass its path with -render-browser)")
}

// Chrome renders pages with a local headless browser.
type Chrome struct {
	Path      string        // browser binary
	Timeout   time.Duration // hard limit per page, process included
	Settle    time.Duration // virtual time given to the page's scripts
	Proxy     string        // optional proxy URL
	Insecure  bool          // accept invalid TLS certificates
	UserAgent string
	MaxBytes  int64 // cap on the DOM read back
}

// maxDOM is the default cap on a rendered DOM.
const maxDOM = 4 << 20

// args builds the browser command line for rawURL. The browser is confined
// to the target's host: every other hostname is mapped to an unresolvable
// address, so third-party scripts, trackers and fonts referenced by the
// page are not fetched and rendering cannot wander off the target.
func (c *Chrome) args(rawURL, profileDir string) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("cannot render %q", rawURL)
	}
	settle := c.Settle
	if settle <= 0 {
		settle = 4 * time.Second
	}
	a := []string{
		"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--disable-extensions", "--disable-background-networking", "--disable-sync",
		"--disable-component-update", "--disable-default-apps", "--mute-audio",
		"--hide-scrollbars", "--disable-notifications", "--disable-popup-blocking",
		"--block-new-web-contents", "--incognito",
		"--user-data-dir=" + profileDir,
		fmt.Sprintf("--virtual-time-budget=%d", settle.Milliseconds()),
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE " + u.Hostname(),
		"--dump-dom",
	}
	if c.UserAgent != "" {
		a = append(a, "--user-agent="+c.UserAgent)
	}
	if c.Proxy != "" {
		a = append(a, "--proxy-server="+c.Proxy)
	}
	if c.Insecure {
		a = append(a, "--ignore-certificate-errors")
	}
	return append(a, rawURL), nil
}

// DOM loads rawURL, lets its scripts run, and returns the resulting DOM as
// HTML. The browser runs with its own sandbox enabled and a throw-away
// profile that is deleted afterwards.
func (c *Chrome) DOM(ctx context.Context, rawURL string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("refusing to start a browser as root (Chrome's sandbox cannot run as root, and rendering untrusted pages without it is unsafe) — run hellhound as a normal user to use -render")
	}
	profile, err := os.MkdirTemp("", "hellhound-render-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(profile)

	args, err := c.args(rawURL, profile)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command(c.Path, args...)
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	isolate(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting browser: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			killTree(cmd)
		case <-done:
		}
	}()

	limit := c.MaxBytes
	if limit <= 0 {
		limit = maxDOM
	}
	var buf bytes.Buffer
	_, readErr := io.Copy(&buf, io.LimitReader(out, limit))
	if int64(buf.Len()) >= limit {
		killTree(cmd) // more than we will use; do not wait for the rest
	}
	waitErr := cmd.Wait()
	close(done)

	if ctx.Err() != nil {
		return nil, fmt.Errorf("rendering %s: %w", rawURL, ctx.Err())
	}
	if buf.Len() == 0 {
		if waitErr != nil {
			return nil, fmt.Errorf("browser failed: %v", waitErr)
		}
		if readErr != nil {
			return nil, readErr
		}
		return nil, errors.New("browser produced no output")
	}
	return buf.Bytes(), nil
}

// Describe returns a one-line description for logs.
func (c *Chrome) Describe() string {
	return strings.TrimSpace(c.Path)
}
