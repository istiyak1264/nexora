package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type ProviderCfg struct {
	Enabled bool    `yaml:"enabled"`
	APIKey  string  `yaml:"api_key"`
	RPS     float64 `yaml:"requests_per_second"`
	Timeout int     `yaml:"timeout_seconds"`
}
type Settings struct {
	Timeout       int     `yaml:"timeout_seconds"`
	Concurrency   int     `yaml:"concurrency"`
	RPS           float64 `yaml:"requests_per_second"`
	MaxCandidates int     `yaml:"max_candidates"`
	UserAgent     string  `yaml:"user_agent"`
}
type Config struct {
	Settings  Settings               `yaml:"settings"`
	Providers map[string]ProviderCfg `yaml:"providers"`
}
type DNSRecords struct {
	A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, CAA []string `json:",omitempty"`
	Status                                     string   `json:"status,omitempty"`
}
type WebMeta struct {
	URL    string   `json:"url"`
	Status int      `json:"status"`
	Title  string   `json:"title,omitempty"`
	Server string   `json:"server,omitempty"`
	Tech   []string `json:"technologies,omitempty"`
	Error  string   `json:"error,omitempty"`
}
type Finding struct {
	Subdomain  string     `json:"subdomain"`
	RootDomain string     `json:"root_domain"`
	Sources    []string   `json:"sources"`
	DNS        DNSRecords `json:"dns,omitempty"`
	Web        []WebMeta  `json:"web,omitempty"`
	ObservedAt string     `json:"observed_at"`
}
type Provider interface {
	Name() string
	Collect(context.Context, string) ([]string, error)
}
type httpProvider struct {
	name, endpoint, key, ua string
	client                  *http.Client
}

type throttledProvider struct {
	Provider
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func (p *throttledProvider) Collect(ctx context.Context, domain string) ([]string, error) {
	if p.interval > 0 {
		p.mu.Lock()
		now := time.Now()
		if p.next.After(now) {
			delay := time.Until(p.next)
			p.mu.Unlock()
			t := time.NewTimer(delay)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-t.C:
			}
			p.mu.Lock()
		}
		if now := time.Now(); p.next.Before(now) {
			p.next = now
		}
		p.next = p.next.Add(p.interval)
		p.mu.Unlock()
	}
	return p.Provider.Collect(ctx, domain)
}

func (p httpProvider) Name() string { return p.name }
func (p httpProvider) Collect(ctx context.Context, domain string) ([]string, error) {
	ep := strings.ReplaceAll(p.endpoint, "{domain}", url.QueryEscape(domain))
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
	if e != nil {
		return nil, e
	}
	if p.key != "" {
		req.Header.Set("X-Api-Key", p.key)
		req.Header.Set("Authorization", "Bearer "+p.key)
	}
	req.Header.Set("User-Agent", p.ua)
	resp, e := p.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s returned %s", p.name, resp.Status)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 12<<20))
	if e != nil {
		return nil, e
	}
	return extractHosts(string(b), domain), nil
}

var hostRE = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`)

func extractHosts(s, domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	seen := map[string]bool{}
	out := []string{}
	for _, m := range hostRE.FindAllString(s, -1) {
		h := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(m, "*."), "."))
		if h == domain || strings.HasSuffix(h, "."+domain) {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}
func env(v string) string {
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		return os.Getenv(v[2 : len(v)-1])
	}
	return v
}
func loadConfig(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	if e = yaml.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.Settings.Timeout < 5 {
		c.Settings.Timeout = 20
	}
	if c.Settings.Concurrency < 1 {
		c.Settings.Concurrency = 8
	}
	if c.Settings.MaxCandidates < 1 {
		c.Settings.MaxCandidates = 100000
	}
	if c.Settings.UserAgent == "" {
		c.Settings.UserAgent = "Nexora/0.2 authorized-security-research"
	}
	return c, nil
}
func passiveProviders(c Config) []Provider {
	endpoints := map[string]string{"crtsh": "https://crt.sh/?q=%25.{domain}&output=json", "certspotter": "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}", "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", "urlscan": "https://urlscan.io/api/v1/search/?q=domain:{domain}", "virustotal": "https://www.virustotal.com/api/v3/domains/{domain}/relationships/subdomains?limit=40", "securitytrails": "https://api.securitytrails.com/v1/domain/{domain}/subdomains", "shodan": "https://api.shodan.io/dns/domain/{domain}?key={key}", "chaos": "https://dns.projectdiscovery.io/dns/{domain}", "anubisdb": "https://anubisdb.com/subdomains/{domain}", "bufferover": "https://tls.bufferover.run/dns?q=.{domain}",
		"wayback":     "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&filter=statuscode:200&collapse=urlkey&limit=5000",
		"github":      "https://api.github.com/search/code?q={domain}&per_page=100",
		"commoncrawl": "https://index.commoncrawl.org/CC-MAIN-2026-30-index?url=*.{domain}/*&output=json&filter=status:200&collapse=urlkey&limit=5000"}
	out := []Provider{}
	for n, pc := range c.Providers {
		if !pc.Enabled {
			continue
		}
		ep, ok := endpoints[n]
		if !ok {
			continue
		}
		ep = strings.ReplaceAll(ep, "{key}", url.QueryEscape(env(pc.APIKey)))
		timeout := pc.Timeout
		if timeout < 1 {
			timeout = c.Settings.Timeout
		}
		client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
		base := httpProvider{name: n, endpoint: ep, key: env(pc.APIKey), ua: c.Settings.UserAgent, client: client}
		rps := pc.RPS
		if rps <= 0 {
			rps = c.Settings.RPS
		}
		interval := time.Duration(0)
		if rps > 0 {
			interval = time.Duration(float64(time.Second) / rps)
		}
		out = append(out, &throttledProvider{Provider: base, interval: interval})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func normalize(h, domain string) string {
	h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
	h = strings.TrimPrefix(h, "*.")
	if h == domain || strings.HasSuffix(h, "."+domain) {
		return h
	}
	return ""
}
func allowed(h string, roots, excludes []string) bool {
	for _, x := range excludes {
		if x != "" && (h == x || strings.HasSuffix(h, "."+x)) {
			return false
		}
	}
	for _, r := range roots {
		if h == r || strings.HasSuffix(h, "."+r) {
			return true
		}
	}
	return false
}
func readScope(domainFlag, scopeFile string) ([]string, error) {
	vals := []string{}
	for _, d := range strings.Split(domainFlag, ",") {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d != "" {
			vals = append(vals, d)
		}
	}
	if scopeFile != "" {
		b, e := os.ReadFile(scopeFile)
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(string(b), "\n") {
			d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]), "."))
			if d != "" {
				vals = append(vals, d)
			}
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, d := range vals {
		if strings.ContainsAny(d, "/: ") || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("no valid authorized root domains supplied")
	}
	return out, nil
}
func resolveRecords(ctx context.Context, h string) (DNSRecords, error) {
	r := net.Resolver{}
	out := DNSRecords{Status: "NODATA"}
	var mu sync.Mutex
	var wg sync.WaitGroup
	lookup := func(kind string, fn func() (any, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := fn()
			if e == nil {
				mu.Lock()
				switch kind {
				case "a":
					out.A = v.([]string)
				case "aaaa":
					out.AAAA = v.([]string)
				case "cname":
					out.CNAME = []string{v.(string)}
				case "mx":
					for _, x := range v.([]*net.MX) {
						out.MX = append(out.MX, x.Host)
					}
				case "ns":
					for _, x := range v.([]*net.NS) {
						out.NS = append(out.NS, x.Host)
					}
				case "txt":
					out.TXT = v.([]string)
				}
				out.Status = "NOERROR"
				mu.Unlock()
			}
		}()
	}
	lookup("a", func() (any, error) {
		v, e := r.LookupHost(ctx, h)
		a := []string{}
		for _, x := range v {
			if net.ParseIP(x).To4() != nil {
				a = append(a, x)
			}
		}
		return a, e
	})
	lookup("aaaa", func() (any, error) {
		v, e := r.LookupHost(ctx, h)
		a := []string{}
		for _, x := range v {
			if ip := net.ParseIP(x); ip != nil && ip.To4() == nil {
				a = append(a, x)
			}
		}
		return a, e
	})
	lookup("cname", func() (any, error) { return r.LookupCNAME(ctx, h) })
	lookup("mx", func() (any, error) { return r.LookupMX(ctx, h) })
	lookup("ns", func() (any, error) { return r.LookupNS(ctx, h) })
	lookup("txt", func() (any, error) { return r.LookupTXT(ctx, h) })
	wg.Wait()
	for _, p := range [][]string{out.A, out.AAAA, out.CNAME, out.MX, out.NS, out.TXT} {
		sort.Strings(p)
	}
	if out.Status == "NODATA" {
		return out, fmt.Errorf("no DNS data")
	}
	return out, nil
}
func wildcardIPs(ctx context.Context, domain string) map[string]bool {
	v, _ := resolveRecords(ctx, "nexora-wildcard-check."+domain)
	m := map[string]bool{}
	for _, x := range append(v.A, v.AAAA...) {
		m[x] = true
	}
	return m
}
func discoverWordlist(ctx context.Context, domain, wordlist string, limit, workers int) []string {
	b, e := os.ReadFile(wordlist)
	if e != nil || limit < 1 {
		return nil
	}
	if workers < 1 {
		workers = 1
	}
	wild := wildcardIPs(ctx, domain)
	cand := make([]string, 0, limit)
	seen := map[string]bool{}
	labelRE := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, line := range strings.Split(string(b), "\n") {
		w := strings.ToLower(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		if w == "" || len(w) > 63 || !labelRE.MatchString(w) || seen[w] {
			continue
		}
		seen[w] = true
		cand = append(cand, w+"."+domain)
		if len(cand) >= limit {
			break
		}
	}
	jobs := make(chan string)
	results := make(chan string, len(cand))
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for h := range jobs {
			r, _ := resolveRecords(ctx, h)
			valid := false
			for _, ip := range append(r.A, r.AAAA...) {
				if !wild[ip] {
					valid = true
					break
				}
			}
			if valid {
				results <- h
			}
		}
	}
	if workers > len(cand) {
		workers = len(cand)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

sendJobs:
	for _, h := range cand {
		select {
		case jobs <- h:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	out := make([]string, 0, len(results))
	for h := range results {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
func permutations(seed []string, domain string, limit int) []string {
	labels := []string{"dev", "staging", "stage", "api", "admin", "internal", "test", "uat", "prod", "old", "new", "preview", "qa"}
	out := []string{}
	seen := map[string]bool{}
	for _, h := range seed {
		base := strings.Split(strings.TrimSuffix(h, "."+domain), ".")[0]
		for _, x := range labels {
			for _, c := range []string{x + "-" + base, base + "-" + x, x + "." + base} {
				f := normalize(c+"."+domain, domain)
				if f != "" && !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
				if len(out) >= limit {
					return out
				}
			}
		}
	}
	return out
}
func probe(ctx context.Context, h string) []WebMeta {
	c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	out := []WebMeta{}
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + h
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if e != nil {
			continue
		}
		req.Header.Set("User-Agent", "Nexora/0.2 authorized-security-research")
		resp, e := c.Do(req)
		if e != nil {
			out = append(out, WebMeta{URL: u, Error: e.Error()})
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		title := ""
		if m := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`).FindStringSubmatch(string(b)); len(m) > 1 {
			title = strings.TrimSpace(strings.Join(strings.Fields(m[1]), " "))
		}
		out = append(out, WebMeta{URL: u, Status: resp.StatusCode, Title: title, Server: resp.Header.Get("Server")})
	}
	return out
}
func loadSnapshot(path string) map[string]Finding {
	b, e := os.ReadFile(path)
	if e != nil {
		return map[string]Finding{}
	}
	var xs []Finding
	if json.Unmarshal(b, &xs) != nil {
		return map[string]Finding{}
	}
	m := map[string]Finding{}
	for _, x := range xs {
		m[x.Subdomain] = x
	}
	return m
}
func saveSnapshot(path string, xs []Finding) error {
	b, e := json.MarshalIndent(xs, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}

const version = "0.4.0"

func main() {
	domainFlag := flag.String("domain", "", "authorized root domain(s), comma-separated")
	scopeFile := flag.String("scope-file", "", "file containing authorized root domains")
	exclude := flag.String("exclude", "", "comma-separated excluded suffixes")
	cfgPath := flag.String("provider-config", "provider-config.yml", "provider YAML path")
	configAlias := flag.String("config", "", "alias for -provider-config")
	outPath := flag.String("output", "", "output path; default stdout")
	outputAlias := flag.String("o", "", "alias for -output")
	snapshot := flag.String("snapshot", "", "save JSON snapshot")
	diff := flag.String("diff", "", "compare against prior JSON snapshot")
	jsonl := flag.Bool("jsonl", false, "emit JSONL")
	records := flag.Bool("records", false, "collect structured DNS records")
	webProbe := flag.Bool("web-probe", false, "opt-in HTTP metadata probes on discovered hosts")
	activeFlag := flag.Bool("active", false, "enable DNS wordlist validation")
	wordlist := flag.String("wordlist", "", "wordlist for active validation")
	permute := flag.Bool("permute", false, "generate conservative permutations")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("nexora", version)
		return
	}
	if *configAlias != "" {
		*cfgPath = *configAlias
	}
	if *outputAlias != "" {
		*outPath = *outputAlias
	}
	roots, e := readScope(*domainFlag, *scopeFile)
	if e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(2)
	}
	ex := []string{}
	for _, x := range strings.Split(*exclude, ",") {
		x = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(x), "."))
		if x != "" {
			ex = append(ex, x)
		}
	}
	cfg, e := loadConfig(*cfgPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Settings.Timeout+120)*time.Second)
	defer cancel()
	findings := map[string]*Finding{}
	var mu sync.Mutex
	collect := func(root string) {
		for _, p := range passiveProviders(cfg) {
			vals, err := p.Collect(ctx, root)

			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s/%s] %v\n", root, p.Name(), err)
				continue
			}
			mu.Lock()
			for _, v := range vals {
				h := normalize(v, root)
				if h != "" && allowed(h, roots, ex) {
					if findings[h] == nil {
						findings[h] = &Finding{Subdomain: h, RootDomain: root, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
					}
					findings[h].Sources = append(findings[h].Sources, p.Name())
				}
			}
			mu.Unlock()
		}
	}
	var wg sync.WaitGroup
	for _, r := range roots {
		r := r
		wg.Add(1)
		go func() { defer wg.Done(); collect(r) }()
	}
	wg.Wait()
	seed := []string{}
	for h := range findings {
		seed = append(seed, h)
	}
	if *permute {
		for _, r := range roots {
			for _, h := range permutations(seed, r, cfg.Settings.MaxCandidates) {
				if allowed(h, roots, ex) && findings[h] == nil {
					findings[h] = &Finding{Subdomain: h, RootDomain: r, Sources: []string{"permutation"}, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
				}
			}
		}
	}
	if *activeFlag {
		if *wordlist == "" {
			fmt.Fprintln(os.Stderr, "error: --active requires --wordlist")
			os.Exit(2)
		}
		for _, r := range roots {
			for _, h := range discoverWordlist(ctx, r, *wordlist, cfg.Settings.MaxCandidates, cfg.Settings.Concurrency) {
				if findings[h] == nil {
					findings[h] = &Finding{Subdomain: h, RootDomain: r, Sources: []string{"dns-bruteforce"}, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
				} else {
					findings[h].Sources = append(findings[h].Sources, "dns-bruteforce")
				}
			}
		}
	}
	xs := []Finding{}
	for _, x := range findings {
		sort.Strings(x.Sources)
		x.Sources = unique(x.Sources)
		if *records {
			x.DNS, _ = resolveRecords(ctx, x.Subdomain)
		}
		if *webProbe {
			x.Web = probe(ctx, x.Subdomain)
		}
		xs = append(xs, *x)
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].Subdomain < xs[j].Subdomain })
	if *snapshot != "" {
		if e := saveSnapshot(*snapshot, xs); e != nil {
			fmt.Fprintln(os.Stderr, "snapshot:", e)
		}
	}
	if *diff != "" {
		old := loadSnapshot(*diff)
		for _, x := range xs {
			if _, ok := old[x.Subdomain]; !ok {
				fmt.Fprintf(os.Stderr, "[new] %s\n", x.Subdomain)
			}
		}
		for h := range old {
			if _, ok := findings[h]; !ok {
				fmt.Fprintf(os.Stderr, "[removed] %s\n", h)
			}
		}
	}
	var w io.Writer = os.Stdout
	var f *os.File
	if *outPath != "" {
		f, e = os.Create(*outPath)
		if e != nil {
			panic(e)
		}
		defer f.Close()
		w = f
	}
	for _, x := range xs {
		if *jsonl {
			b, _ := json.Marshal(x)
			fmt.Fprintln(w, string(b))
		} else {
			fmt.Fprintln(w, x.Subdomain)
		}
	}
}
func unique(xs []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}
