package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Download and merge public resolver lists",
	RunE:  runFetch,
}

func init() {
	fetchCmd.Flags().StringP("output", "o", "resolvers.txt", "output file for merged resolver list")
	fetchCmd.Flags().Bool("local", false, "include regional intranet resolvers from ir-resolvers")
	fetchCmd.Flags().Bool("doh", false, "fetch DoH resolver URLs instead of UDP IPs")
	rootCmd.AddCommand(fetchCmd)
}

var udpResolverSources = []struct {
	name string
	url  string
}{
	{"trickest/resolvers", "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"},
	{"ir-resolvers (local)", "https://raw.githubusercontent.com/net2share/ir-resolvers/main/resolvers.txt"},
}

var dohResolverSources = []struct {
	name string
	url  string
}{
	{"public-doh-servers", "https://raw.githubusercontent.com/crypt0rr/public-doh-servers/master/dns-resolvers.txt"},
}

// Well-known DoH endpoints that are always included
var wellKnownDoH = []string{
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
	"https://dns.quad9.net/dns-query",
	"https://doh.opendns.com/dns-query",
	"https://dns.nextdns.io/dns-query",
	"https://doh.cleanbrowsing.org/doh/security-filter/",
	"https://dns.adguard-dns.com/dns-query",
	"https://doh.mullvad.net/dns-query",
	"https://dns.switch.ch/dns-query",
	"https://dns.digitale-gesellschaft.ch/dns-query",
	"https://doh.libredns.gr/dns-query",
	"https://dns.aa.net.uk/dns-query",
	"https://odvr.nic.cz/dns-query",
	"https://doh.applied-privacy.net/query",
	"https://dns.twnic.tw/dns-query",
	"https://doh-jp.blahdns.com/dns-query",
	"https://doh-de.blahdns.com/dns-query",
	"https://doh.ffmuc.net/dns-query",
	"https://dns.njal.la/dns-query",
}

func runFetch(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	localMode, _ := cmd.Flags().GetBool("local")
	dohMode, _ := cmd.Flags().GetBool("doh")

	seen := make(map[string]struct{})
	var entries []string

	if dohMode {
		// Add well-known DoH endpoints
		for _, url := range wellKnownDoH {
			if _, exists := seen[url]; !exists {
				seen[url] = struct{}{}
				entries = append(entries, url)
			}
		}

		// Fetch from DoH sources
		for _, src := range dohResolverSources {
			fmt.Fprintf(os.Stderr, "fetching %s...\n", src.name)
			urls, err := fetchURLList(src.url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warning: %v\n", err)
				continue
			}
			added := 0
			for _, u := range urls {
				if _, exists := seen[u]; !exists {
					seen[u] = struct{}{}
					entries = append(entries, u)
					added++
				}
			}
			fmt.Fprintf(os.Stderr, "  +%d DoH endpoints\n", added)
		}
	} else {
		// Fetch UDP resolver IPs
		for _, src := range udpResolverSources {
			if src.name == "ir-resolvers (local)" && !localMode {
				continue
			}
			fmt.Fprintf(os.Stderr, "fetching %s...\n", src.name)
			ips, err := fetchIPList(src.url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warning: %v\n", err)
				continue
			}
			added := 0
			for _, ip := range ips {
				if _, exists := seen[ip]; !exists {
					seen[ip] = struct{}{}
					entries = append(entries, ip)
					added++
				}
			}
			fmt.Fprintf(os.Stderr, "  +%d resolvers\n", added)
		}
	}

	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, entry := range entries {
		fmt.Fprintln(f, entry)
	}

	fmt.Fprintf(os.Stderr, "wrote %d entries to %s\n", len(entries), output)
	return nil
}

func fetchIPList(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var ips []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 10*1024*1024))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := line
		if host, _, err := net.SplitHostPort(line); err == nil {
			ip = host
		}
		if net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

func fetchURLList(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var urls []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 10*1024*1024))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "https://") {
			urls = append(urls, line)
		}
	}
	return urls, sc.Err()
}
