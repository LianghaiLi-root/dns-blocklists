# adguard-dns-merged

合并 5 个广告/追踪规则列表，去重后按**匹配语义**拆分为通配与精准两份，供 AdGuard Home 与 sing-box（手机）双端使用。

Generated/updated: 2026-10-17

## 数据源

| # | 列表 | 原始行数 |
|---|------|---------|
| 1 | AdGuard DNS filter (`adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt`) | 185,539 |
| 2 | EasyList China (`217heidai/adblockfilters`) | 17,737 |
| 3 | OISD big (`big.oisd.nl`) | 236,015 |
| 4 | AWAvenue Ads (`TG-Twilight/AWAvenue-Ads-Rule`) | 666 |
| 5 | HaGeZi Pro (`hagezi/dns-blocklists`) | 200,610 |

## 合并结果

| 清单 | 条数 | 匹配语义 | 用途 |
|------|------|----------|------|
| `merged/wildcard.txt` | **463,809** | 域 + 所有子域 | 主体 |
| `merged/exact.txt` | 0 | 仅精确域名 | 占位（本批 5 个来源全部为 `\|\|x^` 通配语法，无 hosts/纯域名来源） |
| `merged/exceptions.txt` | 834 | 例外放行 | 白名单 |

- 去重：63.1 万条通配规则跨 5 列表去重后剩 46.4 万（OISD/HaGeZi/AdGuard 三大全量库重叠约 30%）
- 例外优先：834 个 `@@` 例外域从黑名单同名剔除（与 AdGuard 语义一致）；子域级例外（如 `@@||b.a.com^` vs `\|\|a.com^`）无法在 domain_suffix 模型表达，未做部分剔除
- 剔除：元素隐藏 6,155、URL 路径/无效语法 4,471、正则 587、注释/杂项 1,085、`$badfilter` 4
- **URL 路径规则陷阱**：`\|\|zhihu.com/ads/banner` 这类规则只屏蔽路径不是整个域——合并时整行校验，绝不截断成根域（修复前曾误收 zhihu.com / youtube.com / cloudflare.com 等 2,342 个正常站，已修正并复查 27 个常用域全部干净）
- 自用 DNS 保护：`dns.google`、`dns.alidns.com`、`doh.alidns.com` 强制排除（本次未命中，保护逻辑常驻）

## 产物

| 文件 | 格式 | 用途 |
|------|------|------|
| `singbox/merged-wildcard.srs` | sing-box rule-set 二进制 | **手机 NetProxy**（4.1 MB，463,809 条 domain_suffix） |
| `singbox/src/merged-wildcard.json` | rule-set 源 JSON | 审计/重新编译 |
| `adguard/merged.txt` | AdGuard 语法 `\|\|x^` | AdGuard Home 黑名单 |
| `adguard/exceptions.txt` | AdGuard 语法 `@@\|\|x^` | AdGuard Home 白名单 |
| `merged/*.txt` | 纯域名清单 | 其他工具转换 |

## 复现

```sh
# 1) 更新源列表到 raw/（保持文件名）
# 2) 合并
python3 scripts/merge.py
# 3) 编译 SRS（需要 sing-box 官方二进制）
sing-box rule-set compile --output singbox/merged-wildcard.srs singbox/src/merged-wildcard.json
```

## 手机（NetProxy/sing-box）对接

DNS 规则引用（在 singbox/dns 分区的 rules 头部）：

```json
{"rule_set": ["merged-wildcard"], "action": "reject"}
```

规则集声明（singbox/route 分区，二进制本地文件）：

```json
{"type": "local", "tag": ["merged-wildcard"], "format": "binary", "path": "./rules/local/{tag}.srs"}
```

把 `merged-wildcard.srs` 放到手机 `/data/adb/modules/netproxy/config/singbox/rules/local/`，重启生效。

**与 Lhl 清单的关系**：本仓库替代并涵盖 Lhl 黑名单（Lhl 的 155 条是本集合的子集）。手机端二选一即可，不要同时挂两个全量库。
