package main

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "strings"

    router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
    "google.golang.org/protobuf/proto"
)

type CategoryPolicy struct {
    Name   string `json:"name"`
    Policy string `json:"policy"`
}

type PolicyProfile struct {
    Version    int              `json:"version"`
    Categories []CategoryPolicy `json:"categories"`
}

type ServerManifest struct {
    Name               string   `json:"name"`
    Version            string   `json:"version"`
    DomainSuffixCount  int      `json:"domain_suffix_count"`
    IPv4CIDRCount      int      `json:"ipv4_cidr_count"`
    TotalRules         int      `json:"total_rules"`
    DomainSourceSHA256 string   `json:"domain_source_sha256"`
    DomainParts        []string `json:"domain_parts"`
    IPv4File           string   `json:"ipv4_file"`
}

type OutputManifest struct {
    ServerBlockVersion       string         `json:"server_block_version"`
    ServerBlockDomains       int            `json:"server_block_domains"`
    ServerBlockIPv4          int            `json:"server_block_ipv4"`
    RuBlockedCleaned         int            `json:"ru_blocked_cleaned"`
    RunetSourceCategories    int            `json:"runet_source_categories"`
    HappOutputCategories     int            `json:"happ_output_categories"`
    HappSHA256               string         `json:"happ_sha256"`
    ShadowrocketSHA256       string         `json:"shadowrocket_sha256"`
    ShadowrocketRuleCount    int            `json:"shadowrocket_rule_count"`
    RunetCategoryRuleCounts  map[string]int `json:"runet_category_rule_counts"`
    RunetCategoryPolicies    []CategoryPolicy `json:"runet_category_policies"`
    HappCustomCategories     []string       `json:"happ_custom_categories"`
}

func failf(format string, args ...any) {
    fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
    os.Exit(1)
}

func sha256Bytes(b []byte) string {
    h := sha256.Sum256(b)
    return hex.EncodeToString(h[:])
}

func readUniqueLines(path string) []string {
    b, err := os.ReadFile(path)
    if err != nil { failf("read %s: %v", path, err) }
    seen := map[string]bool{}
    out := []string{}
    for _, raw := range strings.Split(string(b), "\n") {
        line := strings.TrimSpace(raw)
        if line == "" { continue }
        if seen[line] { failf("duplicate in %s: %s", path, line) }
        seen[line] = true
        out = append(out, line)
    }
    return out
}

func loadServerBlock(dir string) ([]string, []string, ServerManifest) {
    manifestPath := filepath.Join(dir, "manifest.json")
    mb, err := os.ReadFile(manifestPath)
    if err != nil { failf("read server manifest: %v", err) }
    var m ServerManifest
    if err := json.Unmarshal(mb, &m); err != nil { failf("decode server manifest: %v", err) }
    if m.Name != "SERVER_BLOCK" || m.Version == "" { failf("invalid server manifest") }

    parts := append([]string(nil), m.DomainParts...)
    if len(parts) == 0 { failf("server manifest has no domain parts") }
    sort.Strings(parts)
    domains := []string{}
    seen := map[string]bool{}
    concat := []byte{}
    for _, name := range parts {
        p := filepath.Join(dir, name)
        b, err := os.ReadFile(p)
        if err != nil { failf("read server domain part %s: %v", p, err) }
        concat = append(concat, b...)
        for _, raw := range strings.Split(string(b), "\n") {
            line := strings.TrimSpace(raw)
            if line == "" { continue }
            fields := strings.Split(line, "\t")
            if len(fields) != 2 || fields[0] != "domain-suffix" { failf("bad server domain line: %q", line) }
            v := fields[1]
            if seen[v] { failf("duplicate server domain: %s", v) }
            seen[v] = true
            domains = append(domains, v)
        }
    }
    if len(domains) != m.DomainSuffixCount { failf("server domains count mismatch: %d != %d", len(domains), m.DomainSuffixCount) }
    if m.DomainSourceSHA256 != "" && sha256Bytes(concat) != m.DomainSourceSHA256 {
        failf("server domain SHA mismatch: got %s expected %s", sha256Bytes(concat), m.DomainSourceSHA256)
    }

    ipv4Lines := readUniqueLines(filepath.Join(dir, m.IPv4File))
    ipv4 := []string{}
    for _, line := range ipv4Lines {
        fields := strings.Split(line, "\t")
        if len(fields) != 2 || fields[0] != "ip-cidr" { failf("bad server IPv4 line: %q", line) }
        ipv4 = append(ipv4, fields[1])
    }
    if len(ipv4) != m.IPv4CIDRCount { failf("server IPv4 count mismatch: %d != %d", len(ipv4), m.IPv4CIDRCount) }
    if len(domains)+len(ipv4) != m.TotalRules { failf("server total mismatch") }
    return domains, ipv4, m
}

func loadPolicy(path string) PolicyProfile {
    b, err := os.ReadFile(path)
    if err != nil { failf("read policy: %v", err) }
    var p PolicyProfile
    if err := json.Unmarshal(b, &p); err != nil { failf("decode policy: %v", err) }
    seen := map[string]bool{}
    for i := range p.Categories {
        p.Categories[i].Name = strings.ToUpper(strings.TrimSpace(p.Categories[i].Name))
        p.Categories[i].Policy = strings.ToUpper(strings.TrimSpace(p.Categories[i].Policy))
        if p.Categories[i].Name == "" { failf("empty category name") }
        if p.Categories[i].Policy != "DIRECT" && p.Categories[i].Policy != "PROXY" { failf("unsupported policy %s", p.Categories[i].Policy) }
        if seen[p.Categories[i].Name] { failf("duplicate policy category %s", p.Categories[i].Name) }
        seen[p.Categories[i].Name] = true
    }
    return p
}

func convertDomain(d *router.Domain, policy string) string {
    if len(d.Attribute) != 0 { failf("Shadowrocket conversion cannot preserve geosite attributes for %s", d.Value) }
    switch d.Type {
    case router.Domain_Full:
        return fmt.Sprintf("DOMAIN,%s,%s", d.Value, policy)
    case router.Domain_RootDomain:
        return fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", d.Value, policy)
    case router.Domain_Plain:
        return fmt.Sprintf("DOMAIN-KEYWORD,%s,%s", d.Value, policy)
    case router.Domain_Regex:
        failf("Shadowrocket conversion does not support geosite regex rule: %s", d.Value)
    default:
        failf("unknown geosite domain type for %s", d.Value)
    }
    return ""
}

func main() {
    basePath := flag.String("runet-geosite", "", "Runet Freedom geosite.dat")
    ruPath := flag.String("ru-cleaned", "", "ru-blocked-cleaned exact hostname list")
    serverDir := flag.String("server-block-dir", "", "canonical SERVER_BLOCK version directory")
    policyPath := flag.String("policy", "", "client category policy JSON")
    happOut := flag.String("happ-output", "", "Happ geosite.dat output")
    srOut := flag.String("shadowrocket-output", "", "Shadowrocket rule-only .conf output")
    manifestOut := flag.String("manifest-output", "", "manifest JSON output")
    flag.Parse()
    for k, v := range map[string]*string{"runet-geosite":basePath,"ru-cleaned":ruPath,"server-block-dir":serverDir,"policy":policyPath,"happ-output":happOut,"shadowrocket-output":srOut,"manifest-output":manifestOut} {
        if *v == "" { failf("--%s is required", k) }
    }

    baseBytes, err := os.ReadFile(*basePath)
    if err != nil { failf("read Runet geosite: %v", err) }
    var base router.GeoSiteList
    if err := proto.Unmarshal(baseBytes, &base); err != nil { failf("decode Runet geosite: %v", err) }
    if len(base.Entry) == 0 { failf("Runet geosite has zero categories") }

    ru := readUniqueLines(*ruPath)
    if len(ru) == 0 { failf("ru-blocked-cleaned is empty") }
    serverDomains, serverIPv4, serverManifest := loadServerBlock(*serverDir)
    policy := loadPolicy(*policyPath)

    // Happ: preserve all Runet Freedom categories, replacing only our custom categories.
    custom := map[string]bool{"RU-BLOCKED-CLEANED":true, "SERVER-BLOCKLIST":true}
    preserved := make([]*router.GeoSite, 0, len(base.Entry)+2)
    for _, site := range base.Entry {
        if custom[strings.ToUpper(site.CountryCode)] { continue }
        preserved = append(preserved, site)
    }
    ruDomains := make([]*router.Domain, 0, len(ru))
    for _, v := range ru { ruDomains = append(ruDomains, &router.Domain{Type:router.Domain_Full, Value:v}) }
    sbDomains := make([]*router.Domain, 0, len(serverDomains))
    for _, v := range serverDomains { sbDomains = append(sbDomains, &router.Domain{Type:router.Domain_RootDomain, Value:v}) }
    happ := &router.GeoSiteList{Entry:append([]*router.GeoSite{}, preserved...)}
    happ.Entry = append(happ.Entry,
        &router.GeoSite{CountryCode:"RU-BLOCKED-CLEANED", Domain:ruDomains},
        &router.GeoSite{CountryCode:"SERVER-BLOCKLIST", Domain:sbDomains},
    )
    happBytes, err := (proto.MarshalOptions{Deterministic:true}).Marshal(happ)
    if err != nil { failf("encode Happ geosite: %v", err) }
    if err := os.MkdirAll(filepath.Dir(*happOut), 0755); err != nil { failf("mkdir Happ output: %v", err) }
    if err := os.WriteFile(*happOut, happBytes, 0644); err != nil { failf("write Happ output: %v", err) }

    // Shadowrocket: explicit first-match rules. ru-blocked-cleaned must precede broad SERVER_BLOCK DIRECT.
    var b strings.Builder
    ruleCount := 0
    b.WriteString("# Generated client routing rules. Rule order is significant.\n")
    b.WriteString("# ru-blocked-cleaned PROXY must stay above SERVER_BLOCK DIRECT.\n")
    b.WriteString("[Rule]\n")
    b.WriteString("# ru-blocked-cleaned -> PROXY\n")
    for _, v := range ru { b.WriteString(fmt.Sprintf("DOMAIN,%s,PROXY\n", v)); ruleCount++ }
    b.WriteString("# SERVER_BLOCK -> DIRECT\n")
    for _, v := range serverDomains { b.WriteString(fmt.Sprintf("DOMAIN-SUFFIX,%s,DIRECT\n", v)); ruleCount++ }
    for _, v := range serverIPv4 { b.WriteString(fmt.Sprintf("IP-CIDR,%s,DIRECT,no-resolve\n", v)); ruleCount++ }

    siteMap := map[string]*router.GeoSite{}
    for _, site := range base.Entry { siteMap[strings.ToUpper(site.CountryCode)] = site }
    categoryCounts := map[string]int{}
    for _, cp := range policy.Categories {
        site := siteMap[cp.Name]
        if site == nil { failf("Runet category not found: %s", cp.Name) }
        b.WriteString(fmt.Sprintf("# geosite:%s -> %s\n", strings.ToLower(cp.Name), cp.Policy))
        seen := map[string]bool{}
        for _, d := range site.Domain {
            line := convertDomain(d, cp.Policy)
            if seen[line] { continue }
            seen[line] = true
            b.WriteString(line+"\n")
            ruleCount++
            categoryCounts[strings.ToLower(cp.Name)]++
        }
    }
    srBytes := []byte(b.String())
    if err := os.MkdirAll(filepath.Dir(*srOut), 0755); err != nil { failf("mkdir Shadowrocket output: %v", err) }
    if err := os.WriteFile(*srOut, srBytes, 0644); err != nil { failf("write Shadowrocket output: %v", err) }

    out := OutputManifest{
        ServerBlockVersion:serverManifest.Version,
        ServerBlockDomains:len(serverDomains),
        ServerBlockIPv4:len(serverIPv4),
        RuBlockedCleaned:len(ru),
        RunetSourceCategories:len(base.Entry),
        HappOutputCategories:len(happ.Entry),
        HappSHA256:sha256Bytes(happBytes),
        ShadowrocketSHA256:sha256Bytes(srBytes),
        ShadowrocketRuleCount:ruleCount,
        RunetCategoryRuleCounts:categoryCounts,
        RunetCategoryPolicies:policy.Categories,
        HappCustomCategories:[]string{"RU-BLOCKED-CLEANED","SERVER-BLOCKLIST"},
    }
    mbytes, _ := json.MarshalIndent(out, "", "  ")
    mbytes = append(mbytes, '\n')
    if err := os.MkdirAll(filepath.Dir(*manifestOut), 0755); err != nil { failf("mkdir manifest output: %v", err) }
    if err := os.WriteFile(*manifestOut, mbytes, 0644); err != nil { failf("write manifest: %v", err) }

    fmt.Printf("SERVER_BLOCK=%s domains=%d ipv4=%d\n", serverManifest.Version, len(serverDomains), len(serverIPv4))
    fmt.Printf("RU_BLOCKED_CLEANED=%d\n", len(ru))
    fmt.Printf("RUNET_CATEGORIES=%d\n", len(base.Entry))
    fmt.Printf("HAPP_CATEGORIES=%d SHA256=%s\n", len(happ.Entry), sha256Bytes(happBytes))
    fmt.Printf("SHADOWROCKET_RULES=%d SHA256=%s\n", ruleCount, sha256Bytes(srBytes))
}
