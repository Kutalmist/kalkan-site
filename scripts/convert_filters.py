#!/usr/bin/env python3
"""Filtre listelerini (Adblock Plus / AdGuard / uBlock sözdizimi) Kalkan'ın kullandığı biçime çevirir.

Çıktılar (out_dir içine):
  <id>.json          Safari/WebKit içerik kuralları (engelleme + CSS gizleme)
  scriptlets.json    Siteye özel scriptlet kuralları (kod değil veri: hangi sitede hangi
                     scriptlet hangi argümanlarla çalışsın). Scriptlet kodu uygulamadadır.
  manifest.json      sürüm + her dosyanın sha256'sı (uygulama indirirken doğrular)

Yalnızca güvenle çevrilebilen kurallar alınır; gelişmiş sözdizimi atlanır.

Kullanım:
  python3 scripts/convert_filters.py <out_dir>                  # tüm listeler
  python3 scripts/convert_filters.py <out_dir> --bundled-only   # uygulamaya gömülecekler

Lisanslar: EasyList/EasyPrivacy CC BY-SA 3.0 + GPLv3 (easylist.to); AdGuard filtreleri GPLv3
(github.com/AdguardTeam/AdguardFilters). AdGuard listeleri uygulamaya gömülmez, çalışırken indirilir.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# (id, kaynak, kategori, uygulamaya gömülsün mü, engelleme kuralları alınsın mı)
LISTS = [
    ("kalkan", os.path.join(HERE, "..", "filters", "kalkan.txt"), "ads", True, True),
    ("easylist", "https://easylist.to/easylist/easylist.txt", "ads", True, True),
    ("adguard-turkish", "https://filters.adtidy.org/ios/filters/13_optimized.txt", "ads", False, True),
    ("adguard-mobile", "https://filters.adtidy.org/ios/filters/11_optimized.txt", "ads", False, True),
    ("easyprivacy", "https://easylist.to/easylist/easyprivacy.txt", "trackers", True, True),
    # AdGuard Base'in engelleme kuralları büyük ölçüde EasyList ile aynı (ve 150 bin sınırını aşar);
    # yalnızca scriptlet kurallarını alıyoruz.
    ("adguard-base", "https://filters.adtidy.org/ios/filters/2_optimized.txt", "ads", False, False),
]
SAFARI_RULE_LIMIT = 150_000

TYPE_MAP = {
    "script": "script", "image": "image", "stylesheet": "style-sheet", "font": "font",
    "media": "media", "subdocument": "document", "xmlhttprequest": "fetch", "websocket": "websocket",
    "ping": "ping", "popup": "popup", "other": "other", "document": "document",
}
KNOWN_OPTS = set(TYPE_MAP) | {"third-party", "3p", "~third-party", "1p", "first-party", "domain", "match-case", "important"}
HOST_RE = re.compile(r"^[a-z0-9.-]+$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9/_.%=&?*^-]*$")
BAD_SELECTOR = re.compile(r":-abp-|:has-text|:contains|:xpath|:upward|:remove|:style|:matches-css|:min-text-length|:watch-attr|\{|\}|\\")

# Uygulamadaki scriptlet kütüphanesinin bildiği adlar (uBlock takma adları AdGuard adına çevrilir)
SCRIPTLETS = {
    "set-constant", "abort-on-property-read", "abort-on-property-write", "abort-current-inline-script",
    "json-prune", "prevent-window-open", "prevent-fetch", "prevent-xhr", "remove-attr", "remove-class",
    "set-cookie", "set-local-storage-item", "set-session-storage-item", "prevent-setTimeout",
    "prevent-setInterval", "prevent-addEventListener", "remove-node-text", "abort-on-stack-trace",
}
UBO_ALIASES = {
    "set": "set-constant", "set-constant": "set-constant", "aopr": "abort-on-property-read",
    "abort-on-property-read": "abort-on-property-read", "aopw": "abort-on-property-write",
    "abort-on-property-write": "abort-on-property-write", "acis": "abort-current-inline-script",
    "acs": "abort-current-inline-script", "abort-current-script": "abort-current-inline-script",
    "json-prune": "json-prune", "nowoif": "prevent-window-open", "no-window-open-if": "prevent-window-open",
    "no-fetch-if": "prevent-fetch", "no-xhr-if": "prevent-xhr", "ra": "remove-attr", "remove-attr": "remove-attr",
    "rc": "remove-class", "remove-class": "remove-class", "nostif": "prevent-setTimeout",
    "no-setTimeout-if": "prevent-setTimeout", "nosiif": "prevent-setInterval",
    "no-setInterval-if": "prevent-setInterval", "aeld": "prevent-addEventListener",
    "addEventListener-defuser": "prevent-addEventListener", "rmnt": "remove-node-text",
    "remove-node-text": "remove-node-text", "aost": "abort-on-stack-trace",
    "abort-on-stack-trace": "abort-on-stack-trace",
}
DOMAIN_ENTRY_RE = re.compile(r"^~?[a-z0-9.*-]+$")


def regex_for(host, path):
    rx = r"^[^:]+:(//)?([^/]+\.)?" + re.escape(host)
    if not path:
        return rx + r"[/:]"
    out = ""
    for ch in path:
        out += ".*" if ch == "*" else r"[/:?=&]" if ch == "^" else re.escape(ch)
    return rx + out


def parse_options(opt_text):
    types, load, if_dom, unless_dom = [], None, [], []
    for opt in opt_text.split(","):
        opt = opt.strip().lower()
        if not opt:
            continue
        name = opt.split("=", 1)[0]
        neg = name.startswith("~")
        bare = name.lstrip("~")
        if bare not in KNOWN_OPTS and name not in KNOWN_OPTS:
            return None
        if bare in ("third-party", "3p"):
            load = "first-party" if neg else "third-party"
        elif bare in ("1p", "first-party"):
            load = "third-party" if neg else "first-party"
        elif bare == "domain":
            for d in opt.split("=", 1)[1].split("|"):
                d = d.strip()
                if not d or "*" in d:
                    continue
                (unless_dom if d.startswith("~") else if_dom).append("*" + d.lstrip("~"))
        elif bare in TYPE_MAP:
            if neg:
                return None
            types.append(TYPE_MAP[bare])
    if if_dom and unless_dom:
        return None
    return types, load, if_dom, unless_dom


def network_rule(line):
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if not body.startswith("||"):
        return None, exception
    pattern, _, opts = body[2:].partition("$")
    m = re.match(r"^([a-z0-9.-]+)(.*)$", pattern.lower())
    if not m:
        return None, exception
    host, path = m.group(1), m.group(2)
    if not HOST_RE.match(host) or "." not in host or not SAFE_PATH_RE.match(path):
        return None, exception
    if path in ("^", "^|"):
        path = ""
    parsed = parse_options(opts) if opts else ([], None, [], [])
    if parsed is None:
        return None, exception
    types, load, if_dom, unless_dom = parsed
    trigger = {"url-filter": regex_for(host, path.rstrip("|"))}
    if types:
        trigger["resource-type"] = sorted(set(types))
    if load:
        trigger["load-type"] = [load]
    if if_dom:
        trigger["if-domain"] = if_dom
    if unless_dom:
        trigger["unless-domain"] = unless_dom
    return {"trigger": trigger, "action": {"type": "ignore-previous-rules" if exception else "block"}}, exception


def split_args(text):
    """'a', "b, c", d  ->  [a, "b, c", d]  (scriptlet argümanları)"""
    args, cur, quote, i = [], "", None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and i + 1 < len(text):
                cur += text[i + 1]; i += 2; continue
            if ch == quote:
                quote = None
            else:
                cur += ch
        elif ch in "'\"":
            quote = ch
        elif ch == ",":
            args.append(cur.strip()); cur = ""
        else:
            cur += ch
        i += 1
    if cur.strip() or args:
        args.append(cur.strip())
    return args


def scriptlet_rule(line):
    """AdGuard:  dom1,dom2#%#//scriptlet('name', 'a', 'b')   (istisna: #@%#)
       uBlock:   dom1,dom2##+js(name, a, b)                   (istisna: #@#+js)"""
    m = re.match(r"^([^#]*)#(@?)%#//scriptlet\((.*)\)\s*$", line)
    if m:
        domains, exc, inner = m.groups()
        args = split_args(inner)
        name = args[0] if args else ""
    else:
        m = re.match(r"^([^#]*)#(@?)#\+js\((.*)\)\s*$", line)
        if not m:
            return None
        domains, exc, inner = m.groups()
        args = split_args(inner)
        name = UBO_ALIASES.get(args[0], "") if args else ""
    name = UBO_ALIASES.get(name, name)
    if name not in SCRIPTLETS:
        return None
    doms = [d.strip().lower() for d in domains.split(",") if d.strip()]
    if any(not DOMAIN_ENTRY_RE.match(d) for d in doms):
        return None
    inc = [d for d in doms if not d.startswith("~")]
    excl = [d[1:] for d in doms if d.startswith("~")]
    rule = {"n": name, "a": args[1:]}
    if inc:
        rule["d"] = inc
    if excl:
        rule["x"] = excl
    return ("exc" if exc else "add", rule)


def convert(text, take_network=True):
    blocks, exceptions, generic_css, site_css, scriptlets = [], [], [], {}, []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if "%#//scriptlet(" in line or "#+js(" in line:
            s = scriptlet_rule(line)
            if s:
                scriptlets.append(s)
            continue
        if not take_network:
            continue
        if "#@#" in line or "#?#" in line or "#$#" in line or "#%#" in line or "#$?#" in line:
            continue
        if "##" in line:
            domains, _, selector = line.partition("##")
            if not selector or BAD_SELECTOR.search(selector) or len(selector) > 300:
                continue
            if not domains:
                generic_css.append(selector)
            else:
                doms = [d.strip() for d in domains.split(",") if d.strip() and not d.strip().startswith("~")]
                doms = [d for d in doms if HOST_RE.match(d)]
                if doms:
                    site_css.setdefault(tuple(sorted(doms)), []).append(selector)
            continue
        if line.startswith("/") and line.endswith("/"):
            continue
        rule, is_exc = network_rule(line)
        if rule:
            (exceptions if is_exc else blocks).append(rule)

    rules = list(blocks)
    for i in range(0, len(generic_css), 250):
        rules.append({"trigger": {"url-filter": ".*"},
                      "action": {"type": "css-display-none", "selector": ", ".join(generic_css[i:i + 250])}})
    for doms, sels in site_css.items():
        for i in range(0, len(sels), 100):
            rules.append({"trigger": {"url-filter": ".*", "if-domain": ["*" + d for d in doms]},
                          "action": {"type": "css-display-none", "selector": ", ".join(sels[i:i + 100])}})
    rules.extend(exceptions)
    return rules, scriptlets


def read_source(src):
    if src.startswith("http"):
        req = urllib.request.Request(src, headers={"User-Agent": "Kalkan-filter-converter"})
        return urllib.request.urlopen(req, timeout=90).read().decode("utf-8", "replace")
    with open(src, encoding="utf-8") as f:
        return f.read()


def write_json(path, obj):
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest(), len(data)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "Shared", "Rules")
    bundled_only = "--bundled-only" in sys.argv
    os.makedirs(out, exist_ok=True)
    manifest = {"version": int(time.time()), "files": []}
    all_scriptlets = {"add": [], "exc": []}
    total = 0
    for list_id, src, category, bundled, take_network in LISTS:
        if bundled_only and not bundled:
            continue
        text = read_source(src)
        version = next((l.split(":", 1)[1].strip() for l in text.splitlines()[:30] if l.startswith("! Version")), "-")
        rules, scriptlets = convert(text, take_network)
        for kind, rule in scriptlets:
            all_scriptlets[kind].append(rule)
        if take_network:
            sha, size = write_json(os.path.join(out, f"{list_id}.json"), rules)
            manifest["files"].append({"id": list_id, "category": category, "file": f"{list_id}.json",
                                      "sha256": sha, "bytes": size, "rules": len(rules), "source_version": version})
            total += len(rules)
        print(f"{list_id:16} {version:22} kural={len(rules) if take_network else '-':>6}  scriptlet={len(scriptlets)}")

    # İstisnaları uygula: aynı ad+argüman için istisna olan alan adlarını kuraldan çıkar
    exc_index = {}
    for e in all_scriptlets["exc"]:
        exc_index.setdefault((e["n"], tuple(e["a"])), set()).update(e.get("d", ["*"]))
    final = []
    for r in all_scriptlets["add"]:
        blocked = exc_index.get((r["n"], tuple(r["a"])), set())
        if "*" in blocked:
            continue
        if blocked and "d" in r:
            r["d"] = [d for d in r["d"] if d not in blocked]
            if not r["d"]:
                continue
        elif blocked:
            r["x"] = sorted(set(r.get("x", [])) | blocked)
        final.append(r)
    sha, size = write_json(os.path.join(out, "scriptlets.json"), final)
    if not bundled_only:
        manifest["files"].append({"id": "scriptlets", "category": "scriptlets", "file": "scriptlets.json",
                                  "sha256": sha, "bytes": size, "rules": len(final)})
        write_json(os.path.join(out, "manifest.json"), manifest)
    print(f"toplam içerik kuralı: {total} (Safari sınırı {SAFARI_RULE_LIMIT}) | scriptlet: {len(final)}")
    if total > SAFARI_RULE_LIMIT:
        sys.exit("HATA: Safari içerik engelleyici sınırı aşıldı")


if __name__ == "__main__":
    main()
