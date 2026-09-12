#!/usr/bin/env python3
from __future__ import annotations
import argparse, base64, json, time
from pathlib import Path
import build_full_client_profiles as c

BASE='https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/client/'
PSETS=['ru-blocked-cleaned.list','meta.list','telegram.list','youtube.list']
DSETS=['server-blocklist.list','category-bank-ru.list','category-ru.list']
DROP=('Facebook/Facebook.list','Instagram/Instagram.list','Whatsapp/Whatsapp.list','Telegram/Telegram.list','YouTube/YouTube.list')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',required=True); ap.add_argument('--managed',required=True)
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    mp,md=c.load_managed(Path(a.managed)); _,manual=c.load_manual(Path('config/client-manual-common.json'))
    manual=[r for r in manual if r[1].lower()!='zonafilm.ru']
    emitted,covered,over=c.filter_manual(manual,mp,md)
    proxy=[r for r in emitted if r[2]=='PROXY']
    direct=[r for r in emitted if r[2]=='DIRECT' and not (r[0]=='domain' and r[1]=='fast.com')]

    t=Path('config/shadowrocket-base-template.conf').read_text(encoding='utf-8')
    t='\n'.join(line for line in t.splitlines() if not any(k in line for k in DROP))+'\n'
    t=t.replace('__VERSION__','2.6.0')
    t=t.replace('__MANAGED_PROXY_RULES__','\n'.join(f'RULE-SET,{BASE+n},PROXY' for n in PSETS))
    t=t.replace('__COMMON_PROXY_RULES__','\n'.join(c.shadow_line(r) for r in proxy))
    t=t.replace('__MANAGED_DIRECT_RULES__','\n'.join(f'RULE-SET,{BASE+n},DIRECT' for n in DSETS))
    t=t.replace('__COMMON_DIRECT_RULES__','\n'.join(c.shadow_line(r) for r in direct))
    t=t.replace('[Rule]\n','[Rule]\nDOMAIN-SUFFIX,fast.com,DIRECT\n',1)
    assert '__' not in t and 'zonafilm.ru' not in t.lower() and len(t.splitlines())<2000
    for n in PSETS+DSETS: assert BASE+n in t
    (out/'shadowrocket.conf').write_text(t,encoding='utf-8',newline='\n')

    h=json.loads(Path('config/happ-base-template.json').read_text(encoding='utf-8'))
    h['Name']='2.6.0'; h['LastUpdated']=int(time.time()); h['Geositeurl']=BASE+'geosite.dat'
    for x in ('geosite:ru-blocked-cleaned','geosite:meta','geosite:telegram','geosite:youtube','geosite:netflix'): h.setdefault('ProxySites',[]).append(x)
    for x in ('geosite:server-blocklist','geosite:category-bank-ru','geosite:category-ru'): h.setdefault('DirectSites',[]).append(x)
    for x in ('geoip:facebook','geoip:telegram','geoip:netflix'): h.setdefault('ProxyIp',[]).append(x)
    for r in emitted:
        tok,bucket=c.happ_token(r)
        key=('ProxySites' if r[2]=='PROXY' else 'DirectSites') if bucket=='site' else ('ProxyIp' if r[2]=='PROXY' else 'DirectIp')
        h.setdefault(key,[]).append(tok)
    sm,ips=c.load_server_ipv4(Path('canonical/server-block/versions/2.5.1')); h.setdefault('DirectIp',[]).extend(ips)
    for k in ('DirectSites','ProxySites','DirectIp','ProxyIp'): h[k]=list(dict.fromkeys(h.get(k,[])))
    assert h['RouteOrder']=='block-proxy-direct' and not any('zonafilm.ru' in s.lower() for s in h['ProxySites']+h['DirectSites'])
    raw=json.dumps(h,ensure_ascii=False,indent=4).encode('utf-8')
    (out/'happ.txt').write_text('happ://routing/add/'+base64.b64encode(raw).decode('ascii')+'\n',encoding='utf-8')
    m={'version':'2.6.0','architecture':'compact-rule-set','shadowrocket_lines':len(t.splitlines()),'manual_source':len(manual),'manual_emitted':len(emitted),'manual_covered':len(covered),'manual_overridden':len(over),'server_block_version':sm['version'],'explicit_zonafilm':False}
    (out/'profile-manifest.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8'); print(json.dumps(m,indent=2))

if __name__=='__main__': main()
