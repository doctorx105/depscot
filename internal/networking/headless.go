package networking

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/rafabd1/DepScout/internal/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// User-Agent pool
// ─────────────────────────────────────────────────────────────────────────────

// userAgentProfile groups a User-Agent string with the browser-fingerprint
// metadata that must stay consistent with it.  Sending mismatched UA / platform
// pairs is a well-known bot-detection signal.
type userAgentProfile struct {
	UA         string
	Platform   string
	AcceptLang string
}

var userAgentPool = []userAgentProfile{
	// Chrome / Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Win32", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "Win32", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36", "Win32", "en-GB,en;q=0.9"},
	{"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Win32", "en-US,en;q=0.9"},
	// Chrome / macOS
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "MacIntel", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "MacIntel", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "MacIntel", "en-US,en;q=0.8"},
	// Chrome / Linux
	{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Linux x86_64", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "Linux x86_64", "en-US,en;q=0.8"},
	// Firefox / Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", "Win32", "en-US,en;q=0.5"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0", "Win32", "en-US,en;q=0.5"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0", "Win32", "en-GB,en;q=0.5"},
	// Firefox / macOS
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:126.0) Gecko/20100101 Firefox/126.0", "MacIntel", "en-US,en;q=0.5"},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0", "MacIntel", "en-US,en;q=0.5"},
	// Firefox / Linux
	{"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0", "Linux x86_64", "en-US,en;q=0.5"},
	// Edge / Windows
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0", "Win32", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0", "Win32", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0", "Win32", "en-US,en;q=0.9"},
	// Safari / macOS
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15", "MacIntel", "en-US,en;q=0.9"},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", "MacIntel", "en-US,en;q=0.9"},
}

// randomProfile returns a uniformly random entry from userAgentPool.
func randomProfile() userAgentProfile {
	return userAgentPool[rand.IntN(len(userAgentPool))]
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-detection script
// ─────────────────────────────────────────────────────────────────────────────

// antiDetectionScript is injected into every new document via
// Page.addScriptToEvaluateOnNewDocument so that it executes before any
// page-level JavaScript has a chance to read the telltale automation
// properties that headless Chrome exposes by default.
const antiDetectionScript = `
(function() {
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true,
    });
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const arr = [1, 2, 3, 4, 5];
            arr.item      = i => arr[i];
            arr.namedItem = () => null;
            arr.refresh   = () => {};
            return arr;
        },
        configurable: true,
    });
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true,
    });
    if (!window.chrome)         window.chrome = {};
    if (!window.chrome.runtime) window.chrome.runtime = {};
})();
`

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// maxConcurrentTabs caps the number of Chrome tabs open simultaneously.
	// Keeping this at 2 prevents Chrome from being overwhelmed on low-RAM
	// systems and eliminates the "websocket url timeout reached" cascade that
	// occurs when too many CDP connections are requested at once.
	maxConcurrentTabs = 2

	// tabRetries is how many times FetchScripts will retry a crawl on a
	// transient WebSocket / CDP error before giving up and falling back to HTTP.
	tabRetries = 3

	// restartEvery triggers a full browser restart after this many completed
	// crawls.  Periodic restarts reclaim memory that Chrome fragments over time
	// and reset any state that leaked between sessions.
	restartEvery = 50
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// isTransientError reports whether err looks like a recoverable Chrome / CDP
// error (WebSocket not ready, target destroyed by a crash, etc.).
// Hard errors from the *target site* (TLS failure, DNS NXDOMAIN) return false
// so they are not retried wastefully.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"websocket",
		"websocket url timeout",
		"no such target",
		"context deadline exceeded",
		"connection reset",
		"eof",
		"cdp",
		"browser closed",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// HeadlessBrowser
// ─────────────────────────────────────────────────────────────────────────────

// HeadlessBrowser manages ONE persistent headless Chrome/Chromium process for
// the entire scan.
//
// # Architecture (single-browser model)
//
// Previous versions called chromedp.NewContext(allocCtx) for every crawl job,
// which caused chromedp to spawn a NEW browser context (and potentially a new
// Chrome process) per target — the root cause of OOM kills.
//
// The corrected model:
//
//	allocCtx   → one ExecAllocator   (manages the Chrome executable)
//	browserCtx → one browser context (the single Chrome window / process)
//	tabCtx     → one per crawl       (an isolated tab inside that window)
//
// Tabs are cheap; browser contexts / processes are expensive.
//
// # Stability mechanisms
//
//   - Semaphore (cap maxConcurrentTabs=2): at most 2 tabs open at once.
//     Acquisition is timed so blocked workers fall back to HTTP rather than
//     sleeping indefinitely.
//   - Periodic restart (every restartEvery=50 crawls): reclaims memory that
//     Chrome fragments over time.  In-flight tabs receive a context-cancelled
//     error, hit the isTransientError path, and are retried in the fresh browser.
//   - Retry loop (up to tabRetries=3): on transient CDP errors each crawl is
//     retried with exponential backoff before falling back to plain HTTP.
//
// # Anti-detection
//
// Allocator flags: disable-blink-features=AutomationControlled,
// exclude-switches=enable-automation, disable-setuid-sandbox.
// Per-crawl: random UA profile (Emulation.setUserAgentOverride) + JS masking
// script injected before page code via Page.addScriptToEvaluateOnNewDocument.
type HeadlessBrowser struct {
	// allocCtx / allocCancel own the Chrome executable lifetime.
	allocCtx    context.Context
	allocCancel context.CancelFunc

	// browserMu guards browserCtx and browserCancel.
	// crawlOnce takes an RLock (many readers); doRestart takes a full Lock.
	browserMu     sync.RWMutex
	browserCtx    context.Context    // single reused browser — NOT recreated per crawl
	browserCancel context.CancelFunc // cancelled on restart or Close

	logger  *utils.Logger
	timeout int

	// sem is a counting semaphore; sending acquires a slot, receiving releases.
	sem chan struct{}

	// crawlCount is incremented atomically for every completed crawl attempt.
	// Used to decide when to trigger a periodic browser restart.
	crawlCount atomic.Int64

	// restartInProgress prevents two goroutines from restarting simultaneously.
	restartInProgress atomic.Bool
}

// NewHeadlessBrowser initialises a headless Chrome/Chromium browser.
//
// One Chrome process is started and kept alive for the entire scan.  All crawl
// jobs open tabs inside that single process; no new processes are spawned per
// target.
//
// skipTLS mirrors --skip-verify: when true Chrome ignores certificate errors.
func NewHeadlessBrowser(logger *utils.Logger, timeout int, skipTLS bool) (*HeadlessBrowser, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// ── Stability ────────────────────────────────────────────────────────
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),

		// Needed when running as root (Docker / Linux CI / WSL).  Without it
		// Chrome refuses to start because the setuid sandbox helper is absent.
		chromedp.Flag("disable-setuid-sandbox", true),

		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-extensions", true),

		// Disable the zygote process to reduce the number of Chrome helper
		// processes.  Each zygote child adds ~30 MB of overhead.
		chromedp.Flag("no-zygote", true),

		// Run renderer, GPU, and browser in a single OS process.
		// Dramatically reduces per-instance memory at the cost of stability:
		// a renderer crash takes down the whole browser (handled by doRestart).
		// Remove this flag if you encounter frequent unexplained crashes.
		chromedp.Flag("single-process", true),

		// Skip image downloads — only script URLs matter for dependency analysis.
		chromedp.Flag("blink-settings", "imagesEnabled=false"),

		// Disable background network activity that wastes memory / bandwidth.
		chromedp.Flag("disable-background-networking", true),

		// ── Anti-detection ───────────────────────────────────────────────────
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("exclude-switches", "enable-automation"),
	)

	if skipTLS {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create the ONE persistent browser context.
	// All tabs will be children of this context.
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	// Probe: run a no-op to confirm Chrome started successfully.
	if err := chromedp.Run(browserCtx); err != nil {
		browserCancel()
		allocCancel()
		return nil, fmt.Errorf(
			"failed to launch headless browser (is Chrome/Chromium installed and in PATH?): %w", err,
		)
	}

	logger.Infof(
		"[Headless] Browser ready — single process, max %d concurrent tab(s), restart every %d crawls.",
		maxConcurrentTabs, restartEvery,
	)

	return &HeadlessBrowser{
		allocCtx:      allocCtx,
		allocCancel:   allocCancel,
		browserCtx:    browserCtx,
		browserCancel: browserCancel,
		logger:        logger,
		timeout:       timeout,
		sem:           make(chan struct{}, maxConcurrentTabs),
	}, nil
}

// doRestart cancels the current browser context and opens a fresh one inside
// the same Chrome executable allocator.  It is safe to call concurrently: only
// the first caller executes the restart; simultaneous callers return immediately.
//
// In-flight crawls whose tab context is a child of the old browserCtx will
// receive a context-cancelled error, which isTransientError classifies as
// retryable.  Their retry will pick up the new browserCtx automatically.
func (h *HeadlessBrowser) doRestart() {
	// Only one restart at a time.
	if !h.restartInProgress.CompareAndSwap(false, true) {
		return
	}
	defer h.restartInProgress.Store(false)

	h.logger.Infof("[Headless] Restarting browser after %d crawls to reclaim memory…", restartEvery)

	// Hold the write lock while swapping contexts so that crawlOnce cannot
	// snapshot a half-replaced browserCtx.
	h.browserMu.Lock()

	// Cancel the old browser (closes all its tabs too).
	h.browserCancel()

	// Create a fresh browser in the same Chrome process pool.
	newCtx, newCancel := chromedp.NewContext(h.allocCtx)
	if err := chromedp.Run(newCtx); err != nil {
		h.logger.Warnf("[Headless] Browser restart failed: %v — will retry on next threshold.", err)
		// The old context is already cancelled.  Best-effort: try to create a
		// new one even after the error so subsequent crawls have something to
		// attach to.  If this also fails, crawls will hit transient errors and
		// fall back to HTTP.
		newCtx, newCancel = chromedp.NewContext(h.allocCtx)
	}

	h.browserCtx = newCtx
	h.browserCancel = newCancel
	h.browserMu.Unlock()

	h.logger.Infof("[Headless] Browser restarted successfully.")
}

// FetchScripts is the public entry point for a single headless crawl.
//
// It:
//  1. Acquires a semaphore slot (max maxConcurrentTabs concurrent crawls).
//  2. Optionally triggers a browser restart when the crawl-count threshold is hit.
//  3. Delegates to crawlOnce, retrying up to tabRetries times on transient errors.
//
// If the semaphore cannot be acquired within timeout+10 s the function returns
// an error immediately so the caller (processHeadlessCrawlJob) can fall back
// to a plain HTTP fetch without blocking its worker goroutine.
func (h *HeadlessBrowser) FetchScripts(targetURL string) ([]string, error) {
	// ── Concurrent-tab guard ─────────────────────────────────────────────────
	slotTimeout := time.Duration(h.timeout+10) * time.Second
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-time.After(slotTimeout):
		return nil, fmt.Errorf(
			"[Headless] all %d tab slot(s) busy after %s — falling back to HTTP for '%s'",
			maxConcurrentTabs, slotTimeout, targetURL,
		)
	}

	// ── Periodic browser restart ─────────────────────────────────────────────
	// Increment first so the very first crawl is count=1, not 0.
	if count := h.crawlCount.Add(1); count%restartEvery == 0 {
		// Run in a goroutine so the current crawl is not delayed.
		// crawlOnce will pick up the new browserCtx on its next iteration if
		// this restart happens to overlap with the current attempt.
		go h.doRestart()
	}

	// ── Retry loop ───────────────────────────────────────────────────────────
	var (
		lastErr    error
		discovered []string
	)

	for attempt := 1; attempt <= tabRetries; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(attempt-1) * time.Second
			h.logger.Debugf(
				"[Headless] Retry %d/%d for '%s' after %s (prev error: %v)",
				attempt, tabRetries, targetURL, backoff, lastErr,
			)
			time.Sleep(backoff)
		}

		discovered, lastErr = h.crawlOnce(targetURL)
		if lastErr == nil {
			return discovered, nil
		}

		if !isTransientError(lastErr) {
			h.logger.Debugf(
				"[Headless] Non-transient error for '%s', skipping retries: %v",
				targetURL, lastErr,
			)
			break
		}
	}

	return nil, fmt.Errorf(
		"headless crawl failed for '%s' after %d attempt(s): %w",
		targetURL, tabRetries, lastErr,
	)
}

// crawlOnce performs one headless navigation to targetURL.
//
// It opens a new tab as a child of the SHARED browserCtx (read under RLock),
// applies the per-crawl anti-detection profile, registers a network interception
// listener, navigates, waits for the page to settle, and then queries the DOM
// for any remaining script references.
//
// All resources (tab context, DevTools session) are released via defer before
// the function returns, so Chrome does not accumulate dangling tabs.
func (h *HeadlessBrowser) crawlOnce(targetURL string) ([]string, error) {
	// ── Snapshot the current browser context under read lock ─────────────────
	// doRestart may swap browserCtx at any time; we take a snapshot so our tab
	// stays attached to a consistent parent for the duration of this crawl.
	h.browserMu.RLock()
	parentCtx := h.browserCtx
	h.browserMu.RUnlock()

	// ── Open an isolated tab ─────────────────────────────────────────────────
	// chromedp.NewContext(browserCtx) creates a new CDP Target (tab) inside
	// the EXISTING browser — it does NOT start a new Chrome process.
	tabCtx, tabCancel := chromedp.NewContext(parentCtx)
	defer tabCancel() // always close the tab when done

	// 60 s per tab: generous enough for slow SPAs, strict enough to avoid
	// worker starvation on unreachable targets.
	tabCtx, tabDeadlineCancel := context.WithTimeout(tabCtx, 60*time.Second)
	defer tabDeadlineCancel()

	// ── Per-crawl anti-detection profile ─────────────────────────────────────
	profile := randomProfile()
	shortUA := profile.UA
	if len(shortUA) > 80 {
		shortUA = shortUA[:80] + "…"
	}
	h.logger.Debugf("[Headless] Profile — UA: %s | platform: %s | lang: %s",
		shortUA, profile.Platform, profile.AcceptLang)

	// ── Deduplicated result set ───────────────────────────────────────────────
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var scriptURLs []string

	record := func(u string) {
		if u == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := seen[u]; !exists {
			seen[u] = struct{}{}
			scriptURLs = append(scriptURLs, u)
		}
	}

	// ── Strategy 1: network interception ─────────────────────────────────────
	// Register BEFORE chromedp.Run so no early Script requests are missed.
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			if e.Type == network.ResourceTypeScript {
				record(e.Request.URL)
				h.logger.Debugf("[Headless] Network script: %s", e.Request.URL)
			}
		}
	})

	// ── Navigate with full anti-detection setup ───────────────────────────────
	err := chromedp.Run(tabCtx,
		network.Enable(),

		// Apply random UA at the emulation layer (covers all HTTP requests).
		emulation.SetUserAgentOverride(profile.UA).
			WithAcceptLanguage(profile.AcceptLang).
			WithPlatform(profile.Platform),

		// Inject masking script before any page JS executes.
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(antiDetectionScript).Do(ctx)
			return err
		}),

		chromedp.Navigate(targetURL),

		// Dwell: let SPAs, lazy-loaders, and framework routers finish their
		// first render cycle before we query the DOM.
		chromedp.Sleep(4*time.Second),
	)

	if err != nil {
		if tabCtx.Err() != nil {
			// Context expired — treat as transient so the retry loop fires.
			return nil, tabCtx.Err()
		}
		// Non-fatal navigation warning (e.g. page returned HTTP 4xx but Chrome
		// still loaded it).  Log and continue — the listener may have captured
		// scripts before the error.
		h.logger.Warnf("[Headless] Navigation warning for '%s': %v", targetURL, err)

		// Propagate transient CDP errors so the retry loop can handle them.
		if isTransientError(err) {
			return nil, err
		}
	}

	// ── Strategy 2: DOM query ─────────────────────────────────────────────────
	// Picks up <script src="…"> elements that were served from the browser
	// cache (cached resources do not fire Network.requestWillBeSent events).
	var domSrcs []string
	_ = chromedp.Run(tabCtx,
		chromedp.Evaluate(
			`Array.from(document.querySelectorAll('script[src]')).map(s => s.src)`,
			&domSrcs,
		),
	)
	for _, s := range domSrcs {
		record(s)
	}

	h.logger.Debugf("[Headless] Unique scripts at '%s': %d", targetURL, len(scriptURLs))
	return scriptURLs, nil
}

// Close releases the browser and the Chrome process allocator.
// It must be called (via defer) once the scan is complete.
func (h *HeadlessBrowser) Close() {
	h.browserMu.Lock()
	h.browserCancel()
	h.browserMu.Unlock()

	h.allocCancel()
}
