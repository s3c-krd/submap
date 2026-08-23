package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

var (
	noColor bool
	silent  bool
)

func color(code, s string) string {
	if noColor || silent {
		return s
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", code, s)
}

func green(s string) string  { return color("32", s) }
func yellow(s string) string { return color("33", s) }
func red(s string) string    { return color("31", s) }
func cyan(s string) string   { return color("36", s) }
func dim(s string) string    { return color("2", s) }
func bold(s string) string   { return color("1", s) }

type Client struct {
	base   string
	cookie string
	apiKey string
	http   *http.Client
}

func NewClient(host string, port int, tls bool) *Client {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, host)
	if (tls && port != 443) || (!tls && port != 80) {
		base = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	return &Client{
		base: base,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, c.base+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	} else if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	for _, ck := range resp.Cookies() {
		c.cookie = ck.Name + "=" + ck.Value
	}
	return resp, nil
}

func (c *Client) json(method, path string, body interface{}) (map[string]interface{}, error) {
	resp, err := c.do(method, path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func (c *Client) Login(user, pass string) error {
	result, err := c.json("POST", "/api/login", map[string]string{
		"username": user, "password": pass,
	})
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	if result["ok"] != true {
		return fmt.Errorf("login failed")
	}
	return nil
}

func (c *Client) Health() (map[string]interface{}, error) {
	return c.json("GET", "/health", nil)
}

type ScanResult struct {
	Domain     string   `json:"domain"`
	Total      int      `json:"total"`
	Cached     bool     `json:"cached"`
	Subdomains []string `json:"subdomains"`
	Error      string   `json:"error,omitempty"`
}

func (c *Client) Scan(domain string) (*ScanResult, error) {
	scanClient := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequest("GET", c.base+"/api/scan?domain="+url.QueryEscape(domain), nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	} else if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}

	resp, err := scanClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") == "application/json" {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if e, ok := errResp["error"].(string); ok {
			return &ScanResult{Domain: domain, Error: e}, nil
		}
	}

	result := &ScanResult{Domain: domain}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lastEvent := ""

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			lastEvent = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(line, "data: ") {
			data := line[6:]
			if lastEvent == "progress" && !silent {
				var p struct {
					Pct   int `json:"pct"`
					Found int `json:"found"`
				}
				json.Unmarshal([]byte(data), &p)
				fmt.Fprintf(os.Stderr, "\r  %s", dim(fmt.Sprintf("[%d%%] %d subdomains found", p.Pct, p.Found)))
			} else if lastEvent == "complete" {
				var comp struct {
					TotalFound int  `json:"totalFound"`
					Cached     bool `json:"cached"`
					Results    []struct {
						Subdomain string `json:"subdomain"`
						Redacted  bool   `json:"redacted"`
					} `json:"results"`
				}
				json.Unmarshal([]byte(data), &comp)
				result.Total = comp.TotalFound
				result.Cached = comp.Cached
				for _, r := range comp.Results {
					if r.Subdomain != "" && !r.Redacted {
						result.Subdomains = append(result.Subdomains, r.Subdomain)
					}
				}
			}
		}
	}

	if !silent {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 60))
	}
	return result, nil
}

func (c *Client) CachedDomains() ([]map[string]interface{}, error) {
	resp, err := c.do("GET", "/api/cache/domains", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `
  %s v%s — Subdomain discovery (144 passive sources)

  %s
    submap -d <domain>                 Scan a single domain
    submap -dL <file>                  Scan domains from file
    submap -d <domain> -o <file>       Save results to file
    submap -d <domain> -json           Output as JSON
    submap -dL <file> -p 5             Scan 5 domains in parallel
    submap --cached                    List cached domains
    submap --count                     Count subdomains only

  %s
    -d  <domain>      Target domain
    -dL <file>        File with domains (one per line)
    -o  <file>        Output file (default: stdout)
    -json             JSON output
    -p  <n>           Parallel scans (default: 1, max: 20)
    -silent           Only print subdomains
    -count            Only print count
    -key <key>        API key (or SUBMAP_KEY env)
    -server <host>    Server host (default: submap.net)
    -port <n>         Server port (default: 443)
    --no-tls          Use HTTP instead of HTTPS
    -u <user>         Username (or SUBMAP_USER env)
    -pw <pass>        Password (or SUBMAP_PASS env)
    --no-color        Disable colors
    --cached          List cached domains in GDrive
    -v, --version     Show version
    -h, --help        Show this help

  %s
    submap -d uber.com -silent | httpx -silent
    submap -dL targets.txt -p 10 -o all-subs.txt
    submap -d hackerone.com -json | jq '.subdomains[]'
    echo "tesla.com" | submap -silent

`, bold("submap"), version, bold("Usage:"), bold("Options:"), bold("Examples:"))
	os.Exit(0)
}

func getArg(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasFlag(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f {
				return true
			}
		}
	}
	return false
}

func main() {
	args := os.Args[1:]

	if hasFlag(args, "-h", "--help") || len(args) == 0 {
		// Check if stdin has data (piped input)
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			// stdin has data, fall through
		} else {
			usage()
		}
	}

	if hasFlag(args, "-v", "--version") {
		fmt.Println("submap v" + version)
		os.Exit(0)
	}

	noColor = hasFlag(args, "--no-color") || os.Getenv("NO_COLOR") != ""
	silent = hasFlag(args, "-silent")
	jsonOut := hasFlag(args, "-json")
	countOnly := hasFlag(args, "-count")

	host := getArg(args, "-server")
	if host == "" {
		host = os.Getenv("SUBMAP_HOST")
	}
	if host == "" {
		host = "submap.net"
	}

	portStr := getArg(args, "-port")
	if portStr == "" {
		portStr = os.Getenv("SUBMAP_PORT")
	}
	if portStr == "" {
		portStr = "443"
	}
	port, _ := strconv.Atoi(portStr)

	apiKey := getArg(args, "-key")
	if apiKey == "" {
		apiKey = os.Getenv("SUBMAP_KEY")
	}

	user := getArg(args, "-u")
	if user == "" {
		user = os.Getenv("SUBMAP_USER")
	}
	if user == "" {
		user = "secscope"
	}

	pass := getArg(args, "-pw")
	if pass == "" {
		pass = os.Getenv("SUBMAP_PASS")
	}

	parallel := 1
	if p := getArg(args, "-p"); p != "" {
		parallel, _ = strconv.Atoi(p)
		if parallel < 1 {
			parallel = 1
		}
		if parallel > 20 {
			parallel = 20
		}
	}

	output := getArg(args, "-o")

	tls := port == 443 || (!hasFlag(args, "-server") && os.Getenv("SUBMAP_HOST") == "")
	if hasFlag(args, "--no-tls") {
		tls = false
	}
	client := NewClient(host, port, tls)

	// Check server
	if _, err := client.Health(); err != nil {
		fmt.Fprintf(os.Stderr, "%s SubMap server not reachable at %s\n", red("[!]"), client.base)
		os.Exit(1)
	}

	if apiKey != "" {
		client.apiKey = apiKey
	} else if pass != "" {
		if err := client.Login(user, pass); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", red("[!]"), err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s No API key provided. Create a free account at %s and generate an API key.\n", yellow("[*]"), client.base)
		fmt.Fprintf(os.Stderr, "    Then run: %s\n\n", dim("export SUBMAP_KEY=\"sk_sub_...\""))
		os.Exit(1)
	}

	// --cached
	if hasFlag(args, "--cached") {
		domains, err := client.CachedDomains()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", red("[!]"), err)
			os.Exit(1)
		}
		if jsonOut {
			data, _ := json.MarshalIndent(domains, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, d := range domains {
				fmt.Printf("%s\t%s\t%s\n", d["domain"], d["size"], d["created"])
			}
			fmt.Fprintf(os.Stderr, "\n%s\n", dim(fmt.Sprintf("%d domains cached", len(domains))))
		}
		return
	}

	// Collect domains
	var domains []string

	if d := getArg(args, "-d"); d != "" {
		domains = append(domains, d)
	}

	if f := getArg(args, "-dL"); f != "" {
		file, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Cannot open %s: %v\n", red("[!]"), f, err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			d := strings.TrimSpace(scanner.Text())
			if d != "" && !strings.HasPrefix(d, "#") {
				domains = append(domains, d)
			}
		}
		file.Close()
	}

	// Check stdin for piped input
	if len(domains) == 0 {
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				d := strings.TrimSpace(scanner.Text())
				if d != "" && !strings.HasPrefix(d, "#") {
					domains = append(domains, d)
				}
			}
		}
	}

	if len(domains) == 0 {
		usage()
	}

	// Output file
	var outFile *os.File
	if output != "" {
		var err error
		outFile, err = os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Cannot create %s: %v\n", red("[!]"), output, err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	if !silent && !jsonOut {
		fmt.Fprintf(os.Stderr, "\n  %s\n\n", bold(fmt.Sprintf("submap — %d domain%s, %d parallel",
			len(domains), map[bool]string{true: "s", false: ""}[len(domains) > 1], parallel)))
	}

	// Scan
	var allResults []*ScanResult
	var mu sync.Mutex
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	write := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		if outFile != nil {
			outFile.WriteString(s + "\n")
		} else if !jsonOut {
			fmt.Println(s)
		}
	}

	for i, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string, num int) {
			defer wg.Done()
			defer func() { <-sem }()

			if !silent && !jsonOut {
				fmt.Fprintf(os.Stderr, "  %s\n", cyan(fmt.Sprintf("[%d/%d] %s", num, len(domains), domain)))
			}

			result, err := client.Scan(domain)
			if err != nil {
				if !silent {
					fmt.Fprintf(os.Stderr, "  %s\n", red(fmt.Sprintf("[%d/%d] %s: %v", num, len(domains), domain, err)))
				}
				result = &ScanResult{Domain: domain, Error: err.Error()}
			} else if result.Error != "" {
				if !silent && !jsonOut {
					fmt.Fprintf(os.Stderr, "  %s\n", red(fmt.Sprintf("[%d/%d] %s: %s", num, len(domains), domain, result.Error)))
				}
			} else {
				if !silent && !jsonOut {
					label := fmt.Sprintf("%d subdomains", result.Total)
					if result.Cached {
						label += " (cached)"
					}
					fmt.Fprintf(os.Stderr, "  %s\n", green(fmt.Sprintf("[%d/%d] %s — %s", num, len(domains), domain, label)))
				}
				if countOnly {
					write(fmt.Sprintf("%s\t%d", domain, result.Total))
				} else if !jsonOut {
					for _, sub := range result.Subdomains {
						write(sub)
					}
				}
			}

			mu.Lock()
			allResults = append(allResults, result)
			mu.Unlock()
		}(domain, i+1)
	}

	wg.Wait()

	if jsonOut {
		var output interface{}
		if len(domains) == 1 {
			output = allResults[0]
		} else {
			output = allResults
		}
		data, _ := json.MarshalIndent(output, "", "  ")
		if outFile != nil {
			outFile.Write(data)
			outFile.WriteString("\n")
		} else {
			fmt.Println(string(data))
		}
	}

	if outFile != nil && !silent {
		fmt.Fprintf(os.Stderr, "\n  %s\n", green("Saved to "+output))
	}

	if !silent && !jsonOut && len(domains) > 1 {
		totalSubs := 0
		for _, r := range allResults {
			totalSubs += r.Total
		}
		fmt.Fprintf(os.Stderr, "\n  %s\n", dim(fmt.Sprintf("%d domains, %d total subdomains", len(allResults), totalSubs)))
	}
}
