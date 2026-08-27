package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func readCanonical(path string, expected int) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		failf("read canonical list: %v", err)
	}
	seen := make(map[string]struct{}, expected)
	var out []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line != raw {
			failf("canonical hostname has surrounding whitespace: %q", raw)
		}
		if _, ok := seen[line]; ok {
			failf("duplicate canonical hostname: %s", line)
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	if len(out) != expected {
		failf("expected %d canonical hostnames, got %d", expected, len(out))
	}
	return out
}

func main() {
	basePath := flag.String("base", "", "Runet Freedom geosite.dat")
	canonicalPath := flag.String("canonical", "", "canonical exact-hostname list")
	outputPath := flag.String("output", "", "merged geosite.dat output")
	category := flag.String("category", "RU-BLOCKED-CLEANED", "category name")
	expected := flag.Int("expected-count", 15759, "expected canonical hostname count")
	flag.Parse()

	if *basePath == "" || *canonicalPath == "" || *outputPath == "" {
		failf("--base, --canonical and --output are required")
	}

	hostnames := readCanonical(*canonicalPath, *expected)

	baseBytes, err := os.ReadFile(*basePath)
	if err != nil {
		failf("read base geosite.dat: %v", err)
	}
	var base router.GeoSiteList
	if err := proto.Unmarshal(baseBytes, &base); err != nil {
		failf("decode base geosite.dat: %v", err)
	}
	if len(base.Entry) == 0 {
		failf("base geosite.dat contains zero categories")
	}

	target := strings.ToUpper(*category)
	preserved := make([]*router.GeoSite, 0, len(base.Entry)+1)
	removedTarget := 0
	for _, site := range base.Entry {
		if strings.EqualFold(site.CountryCode, target) {
			removedTarget++
			continue
		}
		preserved = append(preserved, site)
	}

	domains := make([]*router.Domain, 0, len(hostnames))
	for _, hostname := range hostnames {
		domains = append(domains, &router.Domain{
			Type:  router.Domain_Full,
			Value: hostname,
		})
	}

	merged := &router.GeoSiteList{Entry: make([]*router.GeoSite, 0, len(preserved)+1)}
	merged.Entry = append(merged.Entry, preserved...)
	merged.Entry = append(merged.Entry, &router.GeoSite{
		CountryCode: target,
		Domain:      domains,
	})

	outBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(merged)
	if err != nil {
		failf("encode merged geosite.dat: %v", err)
	}
	if err := os.WriteFile(*outputPath, outBytes, 0644); err != nil {
		failf("write merged geosite.dat: %v", err)
	}

	// Re-read the emitted binary and prove both preservation and the new category.
	checkBytes, err := os.ReadFile(*outputPath)
	if err != nil {
		failf("re-read merged geosite.dat: %v", err)
	}
	var check router.GeoSiteList
	if err := proto.Unmarshal(checkBytes, &check); err != nil {
		failf("decode merged geosite.dat: %v", err)
	}
	if len(check.Entry) != len(preserved)+1 {
		failf("expected %d output categories, got %d", len(preserved)+1, len(check.Entry))
	}

	for i := range preserved {
		if !proto.Equal(preserved[i], check.Entry[i]) {
			failf("upstream category changed during merge at index %d (%s)", i, preserved[i].CountryCode)
		}
	}

	added := check.Entry[len(check.Entry)-1]
	if !strings.EqualFold(added.CountryCode, target) {
		failf("last category is %q, expected %q", added.CountryCode, target)
	}
	if len(added.Domain) != len(hostnames) {
		failf("target category expected %d domains, got %d", len(hostnames), len(added.Domain))
	}
	for i, d := range added.Domain {
		if d.Type != router.Domain_Full {
			failf("target entry %d is not FULL: %v", i, d.Type)
		}
		if d.Value != hostnames[i] {
			failf("target entry %d mismatch: got %q expected %q", i, d.Value, hostnames[i])
		}
	}

	fmt.Printf("source_category_count=%d\n", len(base.Entry))
	fmt.Printf("source_existing_target_categories_removed=%d\n", removedTarget)
	fmt.Printf("preserved_upstream_category_count=%d\n", len(preserved))
	fmt.Printf("output_category_count=%d\n", len(check.Entry))
	fmt.Printf("target_category=%s\n", added.CountryCode)
	fmt.Printf("target_exact_full_count=%d\n", len(added.Domain))
	fmt.Printf("output_size_bytes=%d\n", len(checkBytes))
}
