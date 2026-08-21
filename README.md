# Nexora

Nexora is a provider-configurable, passive-first subdomain discovery CLI for **authorized security assessments and internal asset inventory**. It collects candidate hostnames from certificate-transparency, passive-DNS, URL-index, archive, and other configured sources; normalizes and deduplicates them; preserves source provenance; and optionally validates DNS records or collects low-volume HTTP metadata.

> **Authorization requirement:** Use Nexora only against domains that you own or are explicitly authorized to assess. Nexora intentionally has no unrestricted Internet-wide scanning, stealth, evasion, exploitation, credential attack, crawling, or path-brute-force mode.

## Features

| Capability | Description |
|---|---|
| Passive discovery | Queries enabled provider APIs and extracts hostnames from their responses. |
| Scope control | Accepts one or more authorized root domains, scope files, and exclusions. |
| Provenance | Records which providers contributed each hostname. |
| DNS enrichment | Optionally collects A, AAAA, CNAME, MX, NS, and TXT records. |
| Active validation | Optionally checks a bounded wordlist with a capped worker pool and wildcard filtering. |
| Conservative permutations | Generates a small, auditable set of environment-style candidates from discovered names. |
| HTTP metadata | Optionally records status, title, and Server headers from discovered hosts without following redirects. |
| JSONL output | Produces machine-readable records suitable for pipelines and asset inventories. |
| Snapshots and diffs | Saves findings and reports newly observed or removed hostnames between runs. |
| Provider pacing | Enforces configured per-provider request rates across concurrent domains. |
| Resilient collection | Retries transient network, 429, and 5xx failures with bounded backoff. |
| Concurrent enrichment | Performs optional DNS and HTTP enrichment through a bounded worker pool. |

## Installation

### Use the prebuilt binary

Download or copy the Linux AMD64 binary, make it executable, and place it somewhere on your `PATH`:

```bash
chmod +x nexora-linux-amd64
sudo install -m 0755 nexora-linux-amd64 /usr/local/bin/nexora
nexora -version
```

The binary is platform-specific. Build from source when using another operating system or CPU architecture.

### Build from source

Nexora requires Go 1.22 or newer:

```bash
git clone <your-repository-url> nexora
cd nexora
go mod download
go test ./...
go build -trimpath -ldflags='-s -w' -o nexora ./cmd/nexora
```

Check the installation:

```bash
./nexora -version
./nexora -help
```

## Quick start

The simplest run queries the providers enabled in `provider-config.yml` and prints one normalized hostname per line:

```bash
./nexora -domain example.com
```

For automation, use JSONL and write the results to a file:

```bash
./nexora -domain example.com -jsonl -o results.jsonl
```

The short `-o` option is equivalent to `-output`. The short `-config` option is equivalent to `-provider-config`.

## Command syntax

```text
nexora [options]
```

| Option | Description |
|---|---|
| `-domain example.com` | One authorized root domain. Multiple roots may be comma-separated. |
| `-scope-file scope.txt` | Read authorized root domains from a file. Blank lines and `#` comments are ignored. |
| `-exclude dev.example.com` | Exclude a hostname suffix. Multiple values may be comma-separated. |
| `-provider-config provider-config.yml` | Path to provider configuration. |
| `-config provider-config.yml` | Alias for `-provider-config`. |
| `-output results.txt` | Write output to a file instead of stdout. |
| `-o results.txt` | Alias for `-output`. |
| `-jsonl` | Emit one JSON object per line instead of plain hostnames. |
| `-records` | Add structured DNS records to JSONL findings. |
| `-active -wordlist words.txt` | Enable bounded DNS wordlist validation. |
| `-permute` | Generate conservative permutations from passive results. |
| `-sources a,b,c` | Use only the named configured providers. |
| `-exclude-sources a,b` | Skip named providers even if enabled in the configuration. |
| `-list-sources` | List all built-in provider names and exit. |
| `-web-probe` | Opt in to low-volume HTTP/HTTPS metadata probes. |
| `-snapshot current.json` | Save the current findings as a JSON snapshot. |
| `-diff previous.json` | Report new and removed hostnames against a previous snapshot. |
| `-version` | Print the Nexora version and exit. |
| `-help` | Show the built-in flag reference. |

A domain or scope is required. Nexora rejects values containing URL syntax, spaces, or other invalid scope characters.

## Recommended free profile

The included `provider-config.yml` enables the public/no-key or publicly accessible sources that Nexora supports and enables Shodan through `${SHODAN_API_KEY}`. It disables providers that normally require separate accounts or keys. A strictly no-key run can select only the public sources:

```bash
./nexora \
  -domain example.com \
  -sources crtsh,hackertarget,alienvault,wayback,commoncrawl,anubisdb \
  -jsonl \
  -o results/free.jsonl
```

A run that also uses the user’s Shodan key is:

```bash
export SHODAN_API_KEY='your-real-shodan-key'
./nexora \
  -domain example.com \
  -sources crtsh,hackertarget,alienvault,wayback,commoncrawl,anubisdb,shodan \
  -jsonl \
  -o results/free-plus-shodan.jsonl
```

Use `-list-sources` to see the built-in provider names. Provider selection never overrides authorization scope, response filtering, rate limits, or provider terms.

Transient provider network errors, HTTP 429 responses, and HTTP 5xx responses are retried according to `settings.max_retries` and `settings.retry_backoff_seconds`. Client errors such as 401 and 403 are returned immediately because retrying cannot create authorization. When `-records` or `-web-probe` is enabled, enrichment runs through the bounded `settings.concurrency` worker pool instead of creating one unbounded goroutine per finding.

## Common workflows

### Passive discovery

```bash
./nexora \
  -domain example.com \
  -config ./provider-config.yml \
  -jsonl \
  -o results/example.com.jsonl
```

This is the recommended default workflow. It does not brute-force labels or make HTTP requests to each discovered host.

### Multiple authorized domains

Use a scope file when assessing an approved organization-wide inventory:

```text
# authorized-domains.txt
example.com
example.org
# legacy.example.net
```

Run the collection with exclusions:

```bash
./nexora \
  -scope-file authorized-domains.txt \
  -exclude dev.example.com,legacy.example.org \
  -jsonl \
  -o results/inventory.jsonl
```

### DNS enrichment

```bash
./nexora \
  -domain example.com \
  -records \
  -jsonl \
  -o results/dns.jsonl
```

Each finding may include `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and a DNS `status` field. DNS results are observations at scan time and should not be treated as permanent truth.

### Bounded wordlist validation

Active validation is opt-in. Use it only when the authorization explicitly permits DNS queries against the target:

```bash
./nexora \
  -domain example.com \
  -active \
  -wordlist ./wordlists/subdomains.txt \
  -jsonl \
  -o results/active.jsonl
```

The wordlist stage ignores blank lines, comments, malformed labels, duplicate labels, and labels over 63 characters. Candidate count is capped by `settings.max_candidates`, and DNS work is performed by a bounded worker pool.

### Conservative permutations

```bash
./nexora \
  -domain example.com \
  -permute \
  -jsonl \
  -o results/permutations.jsonl
```

Permutations use a small, auditable set of labels such as `api`, `dev`, `staging`, `admin`, `test`, `uat`, and `preview`. They are candidates, not verified assets, until DNS validation succeeds.

### Optional HTTP metadata

```bash
./nexora \
  -domain example.com \
  -records \
  -web-probe \
  -jsonl \
  -o results/web.jsonl
```

The probe checks HTTP and HTTPS on discovered hostnames, records status, title, and the `Server` header, validates TLS certificates normally, does not follow redirects, and does not crawl, submit forms, brute-force paths, or exploit services. Enable it only when the rules of engagement allow HTTP probing.

### Snapshot and change detection

Create a baseline:

```bash
./nexora \
  -domain example.com \
  -jsonl \
  -snapshot snapshots/example.com.json \
  -o results/baseline.jsonl
```

Compare a later run with the baseline:

```bash
./nexora \
  -domain example.com \
  -jsonl \
  -snapshot snapshots/example.com-latest.json \
  -diff snapshots/example.com.json \
  -o results/latest.jsonl
```

New and removed hostnames are written to stderr as `[new]` and `[removed]` events. JSON output remains suitable for downstream processing.

## Provider configuration

The default file is `provider-config.yml`. This distribution enables public/no-key sources plus Shodan and disables separate account-dependent providers. Secrets should be supplied through environment variables rather than written directly into the file. Configure your Shodan key before running:

```bash
export SHODAN_API_KEY='your-shodan-key'
```

Do not paste a real key into source control or into a shared configuration file.

```yaml
settings:
  timeout_seconds: 20
  concurrency: 8
  requests_per_second: 4
  max_candidates: 100000
  max_retries: 2
  retry_backoff_seconds: 2
  user_agent: "Nexora/0.4 authorized-security-research"

providers:
  crtsh:
    enabled: true
    requests_per_second: 1
  anubisdb:
    enabled: false
    requests_per_second: 0.2
  bufferover:
    enabled: false
    api_key: "${BUFFEROVER_API_KEY}"
    requests_per_second: 0.03
```

A provider is queried only when its `enabled` value is `true`. Provider-specific `requests_per_second` values are enforced across concurrent root domains. If a provider-specific timeout is omitted, the global timeout is used. Nexora does not print configured key values.

### Available providers

| Provider | Typical access | Default state | Notes |
|---|---|---:|---|
| `crtsh` | Public certificate-transparency service | Enabled | Useful for certificate names; subject to service availability. |
| `certspotter` | Free tier with registration/key | Disabled | Enable after setting `CERTSPOTTER_API_KEY`. |
| `hackertarget` | Public/free limited service | Enabled | Host search endpoint and provider quotas apply. |
| `alienvault` | Public/free access with optional key | Enabled | Passive DNS and threat-intelligence data. |
| `urlscan` | Public/free limited service with optional key | Disabled | Enable after reviewing current access terms and setting `URLSCAN_API_KEY` if required. |
| `virustotal` | API key required; free tier is limited | Disabled | Enable after setting `VIRUSTOTAL_API_KEY`. |
| `wayback` | Public archive endpoint | Enabled | Historical URLs may contain stale names. |
| `securitytrails` | Account/key required | Disabled | Enable only with an authorized account. |
| `shodan` | Account/key required | Enabled | Uses `${SHODAN_API_KEY}` from the environment. |
| `chaos` | Account/key required | Disabled | Enable only with an authorized account. |
| `github` | GitHub token recommended/required for useful quotas | Disabled | Searches public code; respect GitHub terms. |
| `commoncrawl` | Public index endpoint | Enabled | Index names change and historical data may be stale. |
| `anubisdb` | Public GET lookup | Enabled | Open subdomain database; use conservatively. |
| `bufferover` | Free limited key-based tier | Disabled | Requires a user-supplied key; documented free tier is quota-limited and non-commercial. |

Do not assume that a free tier means unlimited access, commercial permission, or permission to automate at high volume. Review each provider’s current terms, quotas, and acceptable-use policy before enabling it.

## JSONL output

A JSONL finding has the following general shape:

```json
{
  "subdomain": "api.example.com",
  "root_domain": "example.com",
  "sources": ["crtsh", "anubisdb"],
  "dns": {
    "A": ["192.0.2.10"],
    "status": "NOERROR"
  },
  "observed_at": "2026-08-21T00:00:00Z"
}
```

The exact fields present depend on enabled enrichment options. Plain output contains only normalized hostnames, which is convenient for Unix pipelines:

```bash
./nexora -domain example.com | sort -u > hosts.txt
```

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `no valid authorized root domains supplied` | Missing or malformed `-domain`/`-scope-file` input | Provide a bare domain such as `example.com`, not a URL. |
| Provider returns `401` or `403` | Missing, expired, or unauthorized API key | Set the documented environment variable and verify the provider account. |
| Provider returns `429` | Rate limit exceeded | Lower that provider’s `requests_per_second`, reduce enabled sources, or wait for the quota window. |
| A provider returns no hostnames | The source may have no data, changed its response format, or filtered the domain | Check the provider independently and review stderr; other providers continue. |
| Active mode finds nothing | Wildcard DNS, stale wordlist, or no DNS records | Verify wildcard behavior and use a target-relevant wordlist. |
| HTTP probe reports TLS errors | The host has an invalid or incomplete certificate | Treat the error as observation; Nexora does not disable certificate verification. |
| Results contain old names | Archive and historical sources intentionally include stale observations | Use `-records` and current DNS validation before treating a name as live. |

## Stronger coverage without unsafe behavior

Nexora’s coverage improves by combining independent passive sources, preserving every contributing source, retrying transient provider failures, and validating current DNS only when explicitly requested. It does not equate “more powerful” with indiscriminate Internet scanning. Historical sources can reveal forgotten names, certificate sources can reveal names that were never linked publicly, and passive-DNS sources can reveal names that are absent from current certificates; combining these observations is more useful than relying on one provider.

For the strongest authorized workflow, run a passive baseline, repeat it with the user’s permitted keyed providers, add `-records` for current DNS evidence, and compare snapshots over time:

```bash
./nexora -domain example.com -jsonl -snapshot snapshots/passive.json -o results/passive.jsonl
./nexora -domain example.com -records -jsonl -snapshot snapshots/current.json -diff snapshots/passive.json -o results/current.jsonl
```

## Design limitations

No public passive source can discover every hostname. Private DNS names, never-published names, deleted records, provider quotas, wildcard DNS, incomplete datasets, and changing API contracts create unavoidable blind spots. The appropriate goal is high-confidence, authorized attack-surface discovery with clear provenance, not a claim of Internet-wide completeness.

Nexora intentionally does not implement stealth, evasion, exploitation, credential attacks, unrestricted target expansion, Internet-wide scanning, arbitrary path crawling, or form submission. For private internal names, use an authorized asset inventory, internal DNS export, approved scope feed, or program-provided test environment.

## Development

Run formatting, tests, and a local build before submitting changes:

```bash
gofmt -w cmd/nexora/main.go cmd/nexora/main_test.go
go test ./...
go vet ./...
go build -trimpath -o nexora ./cmd/nexora
```

Provider adapters should be passive, bounded, provenance-preserving, scope-filtered, and respectful of provider terms and rate limits. Avoid adding a provider based only on an unofficial wrapper or an unverified claim of free access.

## License

The project is provided as a foundation for lawful security research and internal asset inventory. Add an appropriate license before public distribution and review all upstream provider terms before enabling integrations.

## References

1. [Anubis DB official API page](https://anubisdb.com/)
2. [BufferOver TLS official service page](https://newtls.bufferover.run/)
3. [SSLMate Certificate Search API](https://sslmate.com/ct_search_api/)
4. [RapidDNS API documentation](https://rapiddns.io/help/api)
