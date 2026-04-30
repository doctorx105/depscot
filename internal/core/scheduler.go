package core

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafabd1/DepScout/internal/config"
	"github.com/rafabd1/DepScout/internal/input"
	"github.com/rafabd1/DepScout/internal/networking"
	"github.com/rafabd1/DepScout/internal/output"
	"github.com/rafabd1/DepScout/internal/report"
	"github.com/rafabd1/DepScout/internal/utils"
)

// JobType defines the kind of work a Job represents.
type JobType int

const (
	// FetchJS downloads the content of a JavaScript file (or an HTML page for
	// crawling purposes).
	FetchJS JobType = iota
	// ProcessJS parses the content of a JavaScript file looking for package names.
	ProcessJS
	// VerifyPackage checks whether a package name exists on the public npm registry.
	VerifyPackage
	// HeadlessCrawl navigates a page URL with a real headless browser so that
	// dynamically injected scripts (webpack lazy chunks, SPA route loads, etc.)
	// are discovered in addition to the static <script src="…"> references.
	HeadlessCrawl
	// ProcessSourceMap parses a JavaScript source map file (.js.map) and
	// extracts dependency names via two strategies:
	//   1. node_modules/<pkg> path segments in the "sources" array.
	//   2. Re-running JS package extraction on every "sourcesContent" entry
	//      (the original, unminified source code of each bundled module).
	ProcessSourceMap
)

func (jt JobType) String() string {
	return [...]string{"FetchJS", "ProcessJS", "VerifyPackage", "HeadlessCrawl", "ProcessSourceMap"}[jt]
}

// Job represents a single unit of work for the worker pool.
type Job struct {
	Input      string
	Type       JobType
	SourceURL  string
	Body       []byte
	BaseDomain string
	Retries    int

	// AutoScheme is true when "https://" was automatically prepended to a bare
	// hostname / subdomain supplied by the user (e.g. "sub.example.com").
	// When set, a connection-level HTTPS failure will transparently retry the
	// same target using "http://" before reporting an error.
	AutoScheme bool

	// NoHeadless prevents the headless-routing branch from firing for this job.
	// It is set on fallback FetchJS jobs that are created after a HeadlessCrawl
	// failure to avoid an infinite headless → fallback → headless loop.
	NoHeadless bool
}

// Scheduler orchestrates the entire scanning pipeline.
type Scheduler struct {
	config          *config.Config
	client          *networking.Client
	processor       *Processor
	domainManager   *networking.DomainManager
	logger          *utils.Logger
	reporter        *report.Reporter
	progBar         *output.ProgressBar
	jobDistributor  *JobDistributor
	headlessBrowser *networking.HeadlessBrowser // nil when --headless is not enabled
	jobsWg          sync.WaitGroup
	producersWg     sync.WaitGroup
	workersWg       sync.WaitGroup
	initialAddWg    sync.WaitGroup
	requestCount    atomic.Int64
	stopRpsCounter  chan bool
}

// NewScheduler creates a new Scheduler.
// headlessBrowser may be nil when headless mode is disabled.
func NewScheduler(
	cfg *config.Config,
	client *networking.Client,
	processor *Processor,
	domainManager *networking.DomainManager,
	logger *utils.Logger,
	reporter *report.Reporter,
	progBar *output.ProgressBar,
	headlessBrowser *networking.HeadlessBrowser,
) *Scheduler {
	return &Scheduler{
		config:          cfg,
		client:          client,
		processor:       processor,
		domainManager:   domainManager,
		logger:          logger,
		reporter:        reporter,
		progBar:         progBar,
		jobDistributor:  NewJobDistributor(cfg.Concurrency, domainManager),
		headlessBrowser: headlessBrowser,
		stopRpsCounter:  make(chan bool),
	}
}

// AddJob is the synchronous method for adding a new job to the pipeline.
// It guarantees the WaitGroup is incremented before the job enters the distributor.
func (s *Scheduler) AddJob(job Job) {
	s.jobsWg.Add(1)
	err := s.jobDistributor.AddJob(job)
	if err != nil {
		s.logger.Errorf("Failed to add job to distributor: %v", err)
		s.jobsWg.Done() // Undo the Add since the job was never queued.
	}
}

// AddJobAsync adds a job without blocking the caller.
// Used when a job handler needs to enqueue child jobs (ProcessJS → VerifyPackage,
// etc.) without risking a deadlock on a full channel.
func (s *Scheduler) AddJobAsync(job Job) {
	s.producersWg.Add(1)
	go func() {
		defer s.producersWg.Done()
		s.AddJob(job)
	}()
}

// requeueJob places a job back into the distributor without incrementing the
// WaitGroup. Used exclusively for 429-retry scenarios where the outstanding WG
// count already covers the re-queued job.
func (s *Scheduler) requeueJob(job Job) {
	err := s.jobDistributor.AddJob(job)
	if err != nil {
		s.logger.Errorf("Failed to requeue job: %v", err)
		s.jobsWg.Done() // Cannot requeue — mark as done to keep accounting correct.
	}
}

// AddInitialTargets normalises and enqueues the initial list of scan targets.
//
// Targets that do not carry a URL scheme (e.g. plain subdomains like
// "api.example.com") are automatically promoted to "https://".  When the HTTPS
// connection fails the fetch layer will transparently retry the same target
// over plain "http://" before surfacing an error.
func (s *Scheduler) AddInitialTargets(targets []string) {
	s.initialAddWg.Add(1)
	go func() {
		defer s.initialAddWg.Done()
		for _, target := range targets {
			if target == "" {
				continue
			}
			normalizedURL, autoScheme := utils.NormalizeTarget(target)
			job := NewJob(normalizedURL, FetchJS)
			job.AutoScheme = autoScheme
			s.AddJob(job)
		}
	}()
}

// StartScan spawns the worker goroutines and the RPS counter.
func (s *Scheduler) StartScan() {
	s.workersWg.Add(s.config.Concurrency)
	for i := 0; i < s.config.Concurrency; i++ {
		go s.worker()
	}
	s.startRpsCounter()
}

// Wait blocks until every job — including all dynamically spawned child jobs —
// has been processed and all workers have exited cleanly.
func (s *Scheduler) Wait() {
	s.initialAddWg.Wait() // Block until all initial targets have been enqueued.
	s.jobsWg.Wait()       // Block until every enqueued job has been processed.
	s.producersWg.Wait()  // Block until all async producer goroutines have exited.
	s.jobDistributor.Close()
	s.workersWg.Wait()
	s.stopRpsCounter <- true
}

func (s *Scheduler) worker() {
	defer s.workersWg.Done()
	workerID := int(s.requestCount.Load()) % s.config.Concurrency

	for {
		job, ok := s.jobDistributor.GetNextJob(workerID)
		if !ok {
			break
		}

		switch job.Type {
		case FetchJS:
			s.processFetchJob(job)
		case ProcessJS:
			s.processor.ProcessJSFileContent(job.SourceURL, job.Body)
			s.handleJobSuccess(job.Input, "ProcessJS")
		case VerifyPackage:
			s.processVerifyPackageJob(job)
		case HeadlessCrawl:
			s.processHeadlessCrawlJob(job)
		case ProcessSourceMap:
			s.processor.ProcessSourceMapContent(job.SourceURL, job.Body)
			s.handleJobSuccess(job.Input, "ProcessSourceMap")
		}
		s.jobsWg.Done()
	}
}

// processFetchJob handles a FetchJS job.
//
// Decision tree (URL-based targets):
//
//  1. Regular HTTP fetch — rate-limiting, 429 retry, connection error handling.
//     When a connection error occurs on an auto-normalised HTTPS target, an
//     http:// version of the job is queued transparently (HTTPS→HTTP fallback).
//
//  2. HTML detection — when the response Content-Type is text/html, the job is
//     either routed to the headless browser (if --headless is on and the domain
//     is not internal) or statically parsed for <script src="…"> tags.
//     Headless routing is intentionally deferred to here — after a successful
//     HTTP response — so that unreachable targets, internal domains, and
//     non-HTML URLs are all filtered out before Chrome is ever involved.
//
//  3. JS processing — non-HTML responses are forwarded to a ProcessJS job for
//     package-name extraction.
func (s *Scheduler) processFetchJob(job Job) {
	isLocalFile := !strings.HasPrefix(job.Input, "http://") && !strings.HasPrefix(job.Input, "https://")
	var body []byte
	var err error
	maxBytes := int64(s.config.MaxFileSize * 1024)

	// ── Local file read ──────────────────────────────────────────────────────
	if isLocalFile {
		s.logger.Debugf("Reading local file: %s", job.Input)

		if !s.config.NoLimit {
			fileInfo, statErr := os.Stat(job.Input)
			if statErr != nil {
				s.handleJobFailure(job, fmt.Errorf("failed to stat local file: %w", statErr))
				return
			}
			if fileInfo.Size() > maxBytes {
				s.logger.Warnf(
					"Skipping local file %s, size (%d KB) exceeds limit (%d KB)",
					job.Input, fileInfo.Size()/1024, s.config.MaxFileSize,
				)
				s.handleJobFailure(job, fmt.Errorf("file size exceeds limit"))
				return
			}
		}

		body, err = os.ReadFile(job.Input)
		if err != nil {
			s.handleJobFailure(job, fmt.Errorf("failed to read local file: %w", err))
			return
		}

	} else {
		// ── 2. Remote URL fetch ───────────────────────────────────────────────
		u, parseErr := url.Parse(job.Input)
		if parseErr != nil {
			s.handleJobFailure(job, parseErr)
			return
		}
		job.BaseDomain = u.Hostname()

		// Wait for the per-domain rate-limiting permit.
		if err := s.domainManager.WaitForPermit(context.Background(), job.BaseDomain); err != nil {
			s.handleJobFailure(job, err)
			return
		}

		s.requestCount.Add(1)

		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Duration(s.config.Timeout)*time.Second,
		)
		defer cancel()

		reqData := networking.RequestData{URL: job.Input, Method: "GET", Ctx: ctx}
		respData := s.client.Do(reqData)

		justDiscarded := s.domainManager.RecordRequestResult(
			job.BaseDomain, respData.StatusCode, respData.Error,
		)
		if justDiscarded {
			s.logger.PublicWarnf(
				"Domain '%s' has been discarded due to excessive 429 responses. "+
					"All subsequent requests to this domain will be ignored.",
				job.BaseDomain,
			)
		}

		// ── 429 retry ─────────────────────────────────────────────────────────
		if respData.StatusCode == 429 {
			if respData.Response != nil {
				respData.Response.Body.Close()
			}
			if job.Retries < 3 {
				job.Retries++
				s.logger.Warnf("Re-queueing job for %s due to 429. Attempt %d.", job.Input, job.Retries)
				s.requeueJob(job)
			} else {
				s.logger.Errorf(
					"Job for %s failed after %d retries due to 429.", job.Input, job.Retries,
				)
				s.handleJobFailure(job, fmt.Errorf("HTTP status 429 after max retries"))
			}
			return
		}

		// ── Connection-level error + HTTPS → HTTP fallback ───────────────────
		// When the target was auto-normalised from a bare hostname to https://
		// and the TLS/TCP connection itself fails, silently create a new FetchJS
		// job using http:// before surfacing an error.  The http:// job carries
		// its own WaitGroup accounting via AddJobAsync.
		if respData.Error != nil {
			if job.AutoScheme && strings.HasPrefix(job.Input, "https://") {
				s.logger.Debugf(
					"HTTPS connection failed for auto-scheme target '%s', retrying with http://.",
					job.Input,
				)
				httpJob := NewJob("http://"+strings.TrimPrefix(job.Input, "https://"), FetchJS)
				httpJob.AutoScheme = false // Don't fall back a second time.
				s.AddJobAsync(httpJob)
				// Progress bar will be updated when the http:// job finishes.
				return
			}
			s.handleJobFailure(job, respData.Error)
			return
		}

		// ── HTTP-level error ──────────────────────────────────────────────────
		if respData.StatusCode >= 400 {
			respData.Response.Body.Close()
			s.handleJobFailure(job, fmt.Errorf("HTTP status %d", respData.StatusCode))
			return
		}

		defer respData.Response.Body.Close()

		// Capture the Content-Type before reading the body so we can branch
		// without having to seek back on the response stream.
		contentType := strings.ToLower(respData.Response.Header.Get("Content-Type"))

		var limitedReader io.Reader = respData.Response.Body
		if !s.config.NoLimit {
			limitedReader = io.LimitReader(respData.Response.Body, maxBytes)
		}
		body, err = io.ReadAll(limitedReader)
		if err != nil {
			s.handleJobFailure(job, err)
			return
		}

		// ── HTML response: headless or static script extraction ───────────────
		// Headless routing lives here — after the HTTP fetch confirms text/html —
		// so Chrome is only invoked for reachable, public HTML pages.
		// Unreachable targets fail at the TCP/TLS level above and never reach
		// this branch.  Internal domains are rejected by IsInternalDomain.
		if strings.Contains(contentType, "text/html") {
			if s.headlessBrowser != nil && !job.NoHeadless && !utils.IsInternalDomain(job.Input) {
				// HTML confirmed and domain is public — hand off to headless for
				// full dynamic-script discovery (webpack lazy chunks, SPA routes, etc.).
				headlessJob := Job{
					Input:      job.Input,
					Type:       HeadlessCrawl,
					SourceURL:  job.Input,
					AutoScheme: job.AutoScheme,
				}
				s.AddJobAsync(headlessJob)
				s.logger.Debugf(
					"[Headless] HTML confirmed at '%s' — routed to browser.", job.Input,
				)
			} else {
				// Headless disabled, domain is internal, or NoHeadless flag set —
				// fall back to fast static <script src="…"> extraction.
				scriptURLs, parseErr := input.ExtractScriptSrcs(body, job.Input)
				if parseErr != nil {
					s.logger.Warnf("Failed to parse HTML from '%s': %v", job.Input, parseErr)
				} else {
					s.logger.Debugf(
						"HTML at '%s' references %d script(s) — queuing for analysis.",
						job.Input, len(scriptURLs),
					)
					for _, scriptURL := range scriptURLs {
						s.AddJobAsync(NewJob(scriptURL, FetchJS))
					}
				}
			}
			s.handleJobSuccess(job.Input, "FetchJS")
			return
		}

		if !s.config.NoLimit && int64(len(body)) == maxBytes {
			s.logger.Warnf(
				"File at %s may have been truncated (reached size limit of %d KB)",
				job.Input, s.config.MaxFileSize,
			)
		}
	}

	// ── 4. Source map or JS processing ───────────────────────────────────────
	// Source map files (.map extension) bypass the normal ProcessJS pipeline
	// and are routed to ProcessSourceMap, which:
	//   a) Scans the "sources" array for node_modules/<pkg> path segments.
	//   b) Re-runs the full JS extraction pipeline on every "sourcesContent"
	//      entry (the unminified originals), respecting --deep-scan.
	if strings.HasSuffix(strings.ToLower(job.Input), ".map") {
		smJob := Job{
			Input:     job.Input,
			Type:      ProcessSourceMap,
			SourceURL: job.SourceURL, // preserve the parent JS URL as the origin
			Body:      body,
		}
		s.AddJobAsync(smJob)
		s.handleJobSuccess(job.Input, "FetchJS")
		return
	}

	// For regular JS files fetched from a URL, check whether the bundler
	// appended a sourceMappingURL annotation (//# sourceMappingURL=…).
	// When found, queue the referenced .map file as a new FetchJS job so
	// its packages are analysed in the same scan.
	if !isLocalFile {
		if mapURL := input.ExtractSourceMapURL(body, job.Input); mapURL != "" {
			s.logger.Debugf("Source map referenced by '%s': %s", job.Input, mapURL)
			mapJob := NewJob(mapURL, FetchJS)
			mapJob.SourceURL = job.Input // propagate parent JS URL as origin
			s.AddJobAsync(mapJob)
		}
	} else {
		// Local JS files: resolve a relative sourceMappingURL path against the
		// directory that contains the JS file and queue it if it exists on disk.
		if rawRef := input.ExtractSourceMapURL(body, ""); rawRef != "" &&
			!strings.HasPrefix(rawRef, "http://") &&
			!strings.HasPrefix(rawRef, "https://") {
			absMapPath := filepath.Join(filepath.Dir(job.Input), rawRef)
			if _, statErr := os.Stat(absMapPath); statErr == nil {
				s.logger.Debugf("Local source map found for '%s': %s", job.Input, absMapPath)
				mapJob := NewJob(absMapPath, FetchJS)
				mapJob.SourceURL = job.Input
				s.AddJobAsync(mapJob)
			}
		}
	}

	processJob := NewJob(job.Input, ProcessJS)
	processJob.SourceURL = job.Input
	processJob.Body = body
	s.AddJobAsync(processJob)

	s.handleJobSuccess(job.Input, "FetchJS")
}

// processHeadlessCrawlJob uses the headless browser to navigate targetURL and
// collect every JavaScript URL requested during the full page lifecycle,
// including those injected dynamically by frameworks and lazy-loaders.
//
// When the headless crawl succeeds each discovered script URL is queued as a
// new FetchJS job, feeding directly into the normal ProcessJS → VerifyPackage
// pipeline.
//
// Two automatic fallbacks protect against edge cases:
//
//  1. Crawl failure (Chrome crash, timeout, DNS error) — a plain FetchJS job
//     is queued with NoHeadless=true so the URL is retried via regular HTTP.
//
//  2. Zero scripts found — the target might be a bare JS endpoint without a
//     .js extension (e.g. /api/bundle served as application/javascript).  The
//     same plain FetchJS fallback is applied so the content is still analysed.
func (s *Scheduler) processHeadlessCrawlJob(job Job) {
	if s.headlessBrowser == nil {
		// Should never happen if the routing logic is correct, but guard anyway.
		s.logger.Errorf(
			"HeadlessCrawl job dispatched but no browser is initialised for '%s'", job.Input,
		)
		return
	}

	// Defence-in-depth: drop internal / private-network targets before Chrome
	// ever opens a connection.  The primary filter is the IsInternalDomain check
	// inside the HTML-detection block of processFetchJob, but this second guard
	// protects against any direct enqueuing paths that may be added in the future.
	if utils.IsInternalDomain(job.Input) {
		s.logger.Debugf("[Headless] Skipping internal/private-network domain: %s", job.Input)
		return
	}

	s.logger.Debugf("[Headless] Starting crawl for '%s'", job.Input)

	scriptURLs, err := s.headlessBrowser.FetchScripts(job.Input)
	if err != nil {
		s.logger.Warnf(
			"[Headless] Crawl failed for '%s': %v — falling back to regular HTTP fetch.",
			job.Input, err,
		)
		fallbackJob := NewJob(job.Input, FetchJS)
		fallbackJob.AutoScheme = job.AutoScheme
		fallbackJob.NoHeadless = true // Prevent re-routing back into headless.
		s.AddJobAsync(fallbackJob)
		return
	}

	s.logger.Debugf("[Headless] Discovered %d script(s) at '%s'", len(scriptURLs), job.Input)

	if len(scriptURLs) == 0 {
		// Nothing found via headless navigation — the URL might be a bare JS
		// endpoint served without a recognised file extension.  Attempt a
		// direct HTTP fetch so the content is still analysed as JavaScript.
		s.logger.Debugf(
			"[Headless] No scripts discovered — attempting direct JS fetch for '%s'.", job.Input,
		)
		fallbackJob := NewJob(job.Input, FetchJS)
		fallbackJob.AutoScheme = job.AutoScheme
		fallbackJob.NoHeadless = true
		s.AddJobAsync(fallbackJob)
		return
	}

	for _, scriptURL := range scriptURLs {
		if scriptURL != "" {
			s.AddJobAsync(NewJob(scriptURL, FetchJS))
		}
	}
	// HeadlessCrawl jobs do not advance the per-file progress bar themselves
	// (same convention as VerifyPackage).  The child FetchJS jobs they spawn
	// will each increment the bar when they complete.
}

func (s *Scheduler) processVerifyPackageJob(job Job) {
	packageName := job.Input
	checkURL := "https://registry.npmjs.org/" + url.PathEscape(packageName)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(s.config.Timeout)*time.Second,
	)
	defer cancel()

	reqData := networking.RequestData{URL: checkURL, Method: "HEAD", Ctx: ctx}
	s.logger.Debugf("Verifying package '%s' at %s", packageName, checkURL)
	s.requestCount.Add(1)

	respData := s.client.Do(reqData)
	if respData.Error != nil {
		s.handleJobFailure(job, respData.Error)
		return
	}
	defer respData.Response.Body.Close()

	switch respData.StatusCode {
	case 404:
		s.logger.Successf("Unclaimed package found: '%s'", packageName)
		s.reporter.AddFinding(report.Finding{
			UnclaimedPackage: packageName,
			FoundInSourceURL: job.SourceURL,
		})
	case 200:
		s.logger.Debugf("Package '%s' is claimed.", packageName)
	default:
		s.logger.Warnf(
			"Unexpected status code %d for package '%s'", respData.StatusCode, packageName,
		)
	}
	s.logger.Debugf("Job succeeded: %s (VerifyPackage)", packageName)
}

// handleJobSuccess increments the progress bar counter for FetchJS jobs and
// emits a debug log entry.
func (s *Scheduler) handleJobSuccess(input, jobType string) {
	if jobType == "FetchJS" {
		s.progBar.Increment()
	}
	s.logger.Debugf("Job succeeded: %s (%s)", input, jobType)
}

// handleJobFailure increments the progress bar counter for FetchJS jobs
// (so the bar keeps moving even when targets fail) and logs the error.
func (s *Scheduler) handleJobFailure(job Job, err error) {
	if job.Type == FetchJS {
		s.progBar.Increment()
	}
	s.logger.Errorf("Job failed: %s (%s). Error: %v", job.Input, job.Type.String(), err)
}

// NewJob is a convenience constructor that fills in the common fields.
func NewJob(input string, jobType JobType) Job {
	return Job{Input: input, SourceURL: input, Type: jobType, Retries: 0}
}

func (s *Scheduler) startRpsCounter() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastCount := int64(0)
		lastTime := time.Now()

		for {
			select {
			case <-s.stopRpsCounter:
				return
			case <-ticker.C:
				currentCount := s.requestCount.Load()
				currentTime := time.Now()
				duration := currentTime.Sub(lastTime).Seconds()
				if duration > 0 {
					rps := float64(currentCount-lastCount) / duration
					s.progBar.SetRPS(rps)
				}
				lastCount = currentCount
				lastTime = currentTime
			}
		}
	}()
}
