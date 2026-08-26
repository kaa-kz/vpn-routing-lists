# vpn-routing-lists

Central repository for reproducible VPN routing lists used by Happ and Shadowrocket.

## Goal

Build a custom category that preserves the upstream logic of `geosite:ru-blocked` while allowing local exceptions:

```text
ru-blocked-custom
=
Community Antifilter
+
Re:filter
+
source/additions.txt
-
source/exclusions.txt
```

The current confirmed exclusion is:

```text
cloudflare-dns.com
```

`cloudflare-ech.com` is documented as a candidate but is not excluded until explicitly approved.

## Repository structure

```text
source/
  exclusions.txt              # suffixes removed from ru-blocked-custom
  additions.txt               # optional local additions
scripts/
  build.py                    # deterministic builder
happ/
  routing-mobile.json         # FakeDNS=true starter profile
  routing-desktop.json        # FakeDNS=false starter profile
shadowrocket/
  example.conf                # remote RULE-SET usage example
.github/workflows/
  update-routing.yml          # monthly/manual build and release
```

## Generated release artifacts

The GitHub Action publishes a clean `release` branch with stable raw URLs:

- `https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/geosite.dat`
- `https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/ru-blocked-custom.txt`
- `https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/shadowrocket-ru-blocked.list`
- `https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/happ-routing-mobile.json`
- `https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/happ-routing-desktop.json`
- `https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/build-metadata.json`

`geosite.dat` is built from the complete current `v2fly/domain-list-community` data directory with one extra category, `geosite:ru-blocked-custom`. Standard categories such as `google`, `youtube`, `category-ru`, etc. therefore remain available to Happ.

## Upstream parity

The custom list downloads the same two source families used by `runetfreedom/russia-blocked-geosite` for its normal `ru-blocked` category:

- `https://community.antifilter.download/list/domains.lst`
- `https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst`

The builder unions them, applies local additions, then removes exclusions by suffix. Excluding `example.com` also removes `sub.example.com` if such a rule appears upstream.

## Happ

Both starter profiles use:

```text
RouteOrder: block-proxy-direct
ProxySites: geosite:ru-blocked-custom
DirectSites: domain:cloudflare-dns.com + geosite:category-ru
Remote DNS: Quad9 DoH
```

The routing database is identical on desktop and mobile. Only the FakeDNS switch differs because current testing shows different platform behaviour:

- mobile: `FakeDNS=true`
- desktop: `FakeDNS=false`

These are starter profiles, not a final full policy. Additional DIRECT/PROXY/BLOCK categories can be added after the routing policy is finalized.

## Shadowrocket

The generated remote list contains entries such as:

```text
DOMAIN-SUFFIX,example.com
```

Example configuration:

```text
[Rule]
DOMAIN,cloudflare-dns.com,DIRECT
RULE-SET,https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/release/shadowrocket-ru-blocked.list,PROXY
FINAL,DIRECT
```

The explicit exception is intentionally above the remote rule-set.

## Automation

`Update routing lists` runs:

- manually through **Actions → Update routing lists → Run workflow**;
- automatically on the first day of each month;
- after relevant source/build files are changed on `main`.

The build fails if `cloudflare-dns.com` is found in the generated custom list.

The `release` branch is generated automatically and should not be edited manually.
