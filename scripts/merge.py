#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并 5 个广告规则列表 -> 通配/精准/例外三份清单 + sing-box SRS + AdGuard 格式。

输入 : raw/*.txt（AdGuard 语法列表）
输出 : merged/wildcard.txt  (通配语义 -> sing-box domain_suffix)
       merged/exact.txt     (精准语义 -> sing-box domain，本批来源为空)
       merged/exceptions.txt(例外白名单)
       singbox/src/*.json   (rule-set 源)
       adguard/merged.txt   (||x^ 格式，AdGuard Home 用)

用法 : python3 scripts/merge.py && sing-box rule-set compile \
         --output singbox/merged-wildcard.srs singbox/src/merged-wildcard.json
"""
import json
import os
import re
from collections import Counter

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RAW = os.path.join(ROOT, "raw")

# 源列表（与 README 的 sources 一一对应）
FILES = [
    ("01-adguard-dns.txt", "AdGuard DNS filter"),
    ("02-easylist-china.txt", "EasyList China"),
    ("03-oisd-big.txt", "OISD big"),
    ("04-awavenue.txt", "AWAvenue Ads"),
    ("05-hagezi-pro.txt", "HaGeZi Pro"),
]

# 自用 DNS 域名（保护，绝不进黑名单）
PROTECTED = {"dns.google", "dns.alidns.com", "doh.alidns.com", "dns64.dns.google"}

# ||domain^ 或 ||domain$modifiers —— 必须整行匹配，拒绝 URL 路径规则（||domain/path）
RE_WILDCARD = re.compile(r"^\|\|([a-z0-9.*-]+\.[a-z]{2,})\^?(?:\$[a-z0-9,_-]+)?$")


def norm_domain(d):
    d = d.strip().strip(".").lower()
    if d.startswith("*."):
        d = d[2:]
    if not d or not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", d) or "." not in d:
        return None
    return d


def merge():
    wildcard, exact, exceptions = set(), set(), set()
    stats = Counter()
    for fn, name in FILES:
        with open(os.path.join(RAW, fn), encoding="utf-8", errors="replace") as f:
            for ln in f:
                s = ln.strip()
                if not s or s.startswith("!") or s.startswith("["):
                    stats["comment"] += 1
                    continue
                if s.startswith("@@"):  # 例外白名单
                    m = re.match(r"^\|\|([a-z0-9.*-]+\.[a-z]{2,})\^?", s[2:])
                    if m:
                        d = norm_domain(m.group(1))
                        if d:
                            exceptions.add(d)
                    stats["exception"] += 1
                    continue
                if "##" in s or "#$#" in s or "#@#" in s:  # 元素隐藏，DNS 层无效
                    stats["cosmetic"] += 1
                    continue
                if s.startswith("/"):  # 正则
                    stats["regex"] += 1
                    continue
                m = re.match(r"^(?:\d{1,3}\.){3}\d{1,3}\s+(\S+)", s)  # hosts 风格 -> 精准
                if m:
                    d = norm_domain(m.group(1))
                    if d and d not in ("localhost", "broadcasthost", "local"):
                        exact.add(d)
                        stats["hosts"] += 1
                    continue
                if s.startswith("||"):  # 通配主形态
                    m = RE_WILDCARD.match(s)
                    if m:
                        if "badfilter" in s:  # 作者撤销的规则
                            stats["badfilter"] += 1
                            continue
                        d = norm_domain(m.group(1))
                        if d:
                            wildcard.add(d)
                            stats["wildcard"] += 1
                        else:
                            stats["invalid"] += 1
                    else:
                        stats["url_path_or_other"] += 1  # ||domain/path 等，剔除
                    continue
                m = re.match(r"^\.([a-z0-9-]+\.[a-z]{2,})\^?$", s)  # 省略 || 的前导点
                if m:
                    d = norm_domain(m.group(1))
                    if d:
                        wildcard.add(d)
                        stats["dot_prefix"] += 1
                    continue
                m = re.match(r"^://\*?\.?([a-z0-9-]+\.[a-z]{2,})\^?$", s)  # URL 中间锚定
                if m:
                    d = norm_domain(m.group(1))
                    if d:
                        wildcard.add(d)
                        stats["url_mid"] += 1
                    continue
                m = re.match(r"^([a-z0-9-]+\.[a-z]{2,})\^?$", s)  # 省略 || 的域名规则
                if m:
                    d = norm_domain(m.group(1))
                    if d:
                        wildcard.add(d)
                        stats["plain_caret"] += 1
                    continue
                m = re.match(r"^([a-z0-9-]+\.[a-z]{2,})$", s)  # 纯域名 -> 精准
                if m:
                    d = norm_domain(m.group(1))
                    if d:
                        exact.add(d)
                        stats["plain"] += 1
                    continue
                stats["dropped"] += 1

    # 例外优先（同名剔除；子域级例外无法在 suffix 模型表达）
    wildcard -= exceptions
    exact -= exceptions
    # 自用 DNS 保护
    hit = (wildcard | exact) & PROTECTED
    wildcard -= PROTECTED
    exact -= PROTECTED
    return wildcard, exact, exceptions, stats, hit


def write_outputs(wildcard, exact, exceptions):
    out = os.path.join(ROOT, "merged")
    os.makedirs(out, exist_ok=True)
    for name, data in (("wildcard", wildcard), ("exact", exact), ("exceptions", exceptions)):
        with open(os.path.join(out, name + ".txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(data)) + ("\n" if data else ""))

    sb = os.path.join(ROOT, "singbox", "src")
    os.makedirs(sb, exist_ok=True)
    with open(os.path.join(sb, "merged-wildcard.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"version": 1, "rules": [{"domain_suffix": sorted(wildcard)}]}, f, ensure_ascii=False)
        f.write("\n")
    with open(os.path.join(sb, "merged-exact.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"version": 1, "rules": [{"domain": sorted(exact)}] if exact else []}, f, ensure_ascii=False)
        f.write("\n")

    ag = os.path.join(ROOT, "adguard")
    os.makedirs(ag, exist_ok=True)
    with open(os.path.join(ag, "merged.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("! Merged ad/tracker blocklist (domain+subdomains)\n")
        for d in sorted(wildcard):
            f.write("||%s^\n" % d)
    with open(os.path.join(ag, "exceptions.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("! Exceptions (whitelist) merged from source lists\n")
        for d in sorted(exceptions):
            f.write("@@||%s^\n" % d)


if __name__ == "__main__":
    wl, ex, exc, stats, hit = merge()
    write_outputs(wl, ex, exc)
    for k, v in stats.most_common():
        print("  %-18s %8d" % (k, v))
    print("\nwildcard(通配): %d\nexact(精准):    %d\nexceptions:     %d\n保护命中:       %s"
          % (len(wl), len(ex), len(exc), sorted(hit) if hit else "无"))
